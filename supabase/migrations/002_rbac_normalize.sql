-- ═══════════════════════════════════════════════════════════════
-- PhysioVerse migration 2: custom roles/permissions + normalized
-- per-resource tables, so RLS can actually enforce "receptionist
-- can't read clinical notes" at the database level — not just hide
-- a nav button.
--
-- Run AFTER migration-1-multitenant.sql, in Supabase SQL Editor.
-- Idempotent-ish (uses IF NOT EXISTS / ON CONFLICT) but this is a
-- structural change — test against a copy of real data first if any
-- clinic has signed up since migration 1, then run the backfill
-- block at the bottom once, per clinic.
-- ═══════════════════════════════════════════════════════════════

-- Wrapped in a transaction: if ANY statement below fails, everything in
-- this file rolls back together — no partial state to clean up before
-- retrying, unlike what happened on the first run before this fix.
begin;

-- ── 1. Permission catalog ─────────────────────────────────────
-- Fixed vocabulary the app understands. Add a row here whenever a
-- new feature needs its own on/off switch in the permissions matrix.
create table if not exists permission_catalog (
  key text primary key,
  category text not null,
  label text not null,
  sort_order int not null default 0
);
insert into permission_catalog(key,category,label,sort_order) values
 ('patients.view','Patients','View patient records',10),
 ('patients.edit','Patients','Add/edit patient records',11),
 ('patients.delete','Patients','Delete patients',12),
 ('clinical.view','Clinical','View assessments, consultation notes, treatment plans',20),
 ('clinical.edit','Clinical','Create/edit assessments, notes, treatment plans',21),
 ('appointments.view','Appointments','View appointments',30),
 ('appointments.edit','Appointments','Create/edit/cancel appointments',31),
 ('billing.view','Billing','View invoices & packages',40),
 ('billing.edit','Billing','Create invoices, record payments, sell packages',41),
 ('expenses.view','Expenses','View clinic expenses',50),
 ('expenses.edit','Expenses','Add/edit clinic expenses',51),
 ('reports.view','Reports','View revenue & performance reports',60),
 ('reminders.view','Reminders','View reminders',70),
 ('reminders.edit','Reminders','Send/schedule reminders',71),
 ('staff.manage','Administration','Manage staff logins & roles',80),
 ('branches.manage','Administration','Manage branches',81),
 ('settings.manage','Administration','Edit clinic settings',82),
 ('audit.view','Administration','View audit log',83),
 ('records.delete','Administration','Permanently delete appointments, invoices, expenses, assessments, treatment plans, packages',84)
on conflict (key) do nothing;

-- ── 2. Roles (per clinic, owner-customizable) ─────────────────
create table if not exists roles (
  id uuid primary key default gen_random_uuid(),
  clinic_id uuid not null references clinics(id) on delete cascade,
  name text not null,
  is_owner_role boolean not null default false,
  permissions jsonb not null default '{}'::jsonb, -- {"patients.view": true, ...}
  created_at timestamptz not null default now(),
  unique(clinic_id, name)
);
alter table roles enable row level security;

-- profiles.role_id replaces the old fixed-enum `role` text column as the
-- source of truth. `role` stays (nullable-in-spirit, still NOT NULL for
-- now) for backward compat with anything still reading it directly —
-- drop it once every code path is confirmed to use role_id/has_permission().
-- Must come BEFORE has_permission() below — it's a `language sql` function,
-- and Postgres validates column references in those at CREATE time, not
-- just on first call. Defining it before this column existed is exactly
-- what caused "column p.role_id does not exist" on the first run of this file.
alter table profiles add column if not exists role_id uuid references roles(id);

create or replace function has_permission(perm text)
returns boolean
language sql stable security definer set search_path = public
as $$
  select coalesce(
    (select (r.permissions->>perm)::boolean
     from profiles p join roles r on r.id = p.role_id
     where p.user_id = auth.uid()),
    false
  )
$$;

-- Owner-role protections: never let a clinic lock itself out.
create or replace function protect_owner_role()
returns trigger language plpgsql as $$
begin
  if TG_OP = 'DELETE' and OLD.is_owner_role then
    raise exception 'The Owner role cannot be deleted';
  end if;
  if TG_OP = 'UPDATE' and OLD.is_owner_role and not (NEW.permissions->>'staff.manage')::boolean then
    raise exception 'The Owner role must always keep staff.manage';
  end if;
  return coalesce(NEW,OLD);
end;
$$;
drop trigger if exists trg_protect_owner_role on roles;
create trigger trg_protect_owner_role before update or delete on roles
  for each row execute function protect_owner_role();

create or replace function prevent_last_owner_removal()
returns trigger language plpgsql as $$
declare
  owner_role_id uuid;
  remaining int;
begin
  select id into owner_role_id from roles where clinic_id = OLD.clinic_id and is_owner_role limit 1;
  if OLD.role_id = owner_role_id then
    select count(*) into remaining from profiles
      where clinic_id = OLD.clinic_id and role_id = owner_role_id and user_id <> OLD.user_id;
    if remaining = 0 then
      raise exception 'A clinic must always have at least one Owner';
    end if;
  end if;
  return OLD;
end;
$$;
drop trigger if exists trg_prevent_last_owner_removal on profiles;
create trigger trg_prevent_last_owner_removal before delete or update on profiles
  for each row when (OLD.role_id is not null) execute function prevent_last_owner_removal();

create policy "roles: read own clinic" on roles for select using (clinic_id = my_clinic_id());
create policy "roles: manage own clinic" on roles for all
  using (clinic_id = my_clinic_id() and has_permission('staff.manage'))
  with check (clinic_id = my_clinic_id() and has_permission('staff.manage'));

-- ── 3. create_clinic_and_owner (v2): also creates the default role set ──
create or replace function create_clinic_and_owner(clinic_name text, owner_name text, owner_email text)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  new_clinic_id uuid;
  owner_role_id uuid;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if exists (select 1 from profiles where user_id = auth.uid()) then
    raise exception 'This login is already linked to a clinic';
  end if;

  insert into clinics(name) values (trim(clinic_name)) returning id into new_clinic_id;

  insert into roles(clinic_id,name,is_owner_role,permissions) values
    (new_clinic_id,'Owner',true,
      (select jsonb_object_agg(key,true) from permission_catalog))
    returning id into owner_role_id;
  insert into roles(clinic_id,name,is_owner_role,permissions) values
    (new_clinic_id,'Therapist',false,
      '{"patients.view":true,"patients.edit":true,"clinical.view":true,"clinical.edit":true,
        "appointments.view":true,"appointments.edit":true,"reminders.view":true}'::jsonb),
    (new_clinic_id,'Receptionist',false,
      '{"patients.view":true,"patients.edit":true,"appointments.view":true,"appointments.edit":true,
        "billing.view":true,"billing.edit":true,"reminders.view":true,"reminders.edit":true}'::jsonb);

  insert into profiles(user_id, clinic_id, role_id, role, name, email)
    values (auth.uid(), new_clinic_id, owner_role_id, 'owner', trim(owner_name), lower(trim(owner_email)));
  -- One default branch — the app's UI assumes at least one branch always exists
  -- (e.g. DB.branches[0] for invoice letterheads). `patients`/`branches` are
  -- normalized tables now, so they're deliberately NOT part of this blob.
  insert into branches(id, clinic_id, name, address, phone) values (gen_random_uuid()::text, new_clinic_id, 'Main Branch', '', '');
  insert into clinic_data(clinic_id, data) values (new_clinic_id, jsonb_build_object(
    'exercisePresets','[]'::jsonb,'customModalities','[]'::jsonb,'billingServices','[]'::jsonb,'exerciseLinks','[]'::jsonb,
    'staff','[]'::jsonb,'attendance','[]'::jsonb,'appointments','[]'::jsonb,'consultations','[]'::jsonb,
    'assessments','[]'::jsonb,'plans','[]'::jsonb,'pkgTemplates','[]'::jsonb,'msgTemplates','[]'::jsonb,
    'patientPkgs','[]'::jsonb,'invoices','[]'::jsonb,'expenses','[]'::jsonb,'reminders','[]'::jsonb,
    'active','[]'::jsonb,'auditLog','[]'::jsonb,
    'settings',jsonb_build_object('wa',true,'sms',true,'leadHrs',24,'payReminder',true,'clinic',trim(clinic_name),'gstin','','msgCredits',0)
  ));
  return new_clinic_id;
end;
$$;
grant execute on function create_clinic_and_owner(text,text,text) to authenticated;

-- ── 4. Normalized resource tables ──────────────────────────────
-- Each gets clinic_id + RLS keyed to has_permission(). Nested,
-- permission-irrelevant substructure (a treatment plan's session
-- log, an assessment's ROM grid) stays as jsonb columns rather than
-- further tables — normalization only goes as deep as the
-- permission matrix needs it to.

create table if not exists branches (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  name text not null default '', address text not null default '', phone text not null default ''
);
alter table branches enable row level security;
create policy "branches: read" on branches for select using (clinic_id = my_clinic_id());
create policy "branches: write" on branches for all
  using (clinic_id = my_clinic_id() and has_permission('branches.manage'))
  with check (clinic_id = my_clinic_id() and has_permission('branches.manage'));

create table if not exists patients (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  name text not null, dob date, age int, gender text, phone text, condition text,
  since date, since_time text, therapist text, branch_id text references branches(id),
  wallet numeric not null default 0, status text not null default 'Active',
  email text, occ text, addr text, em_name text, em_phone text, ref_dr text,
  docs jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
alter table patients enable row level security;
create policy "patients: view" on patients for select using (clinic_id = my_clinic_id() and has_permission('patients.view'));
create policy "patients: insert" on patients for insert with check (clinic_id = my_clinic_id() and has_permission('patients.edit'));
create policy "patients: update" on patients for update using (clinic_id = my_clinic_id() and has_permission('patients.edit'));
create policy "patients: delete" on patients for delete using (clinic_id = my_clinic_id() and has_permission('patients.delete'));

create table if not exists appointments (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  date date not null, time text, type text, therapist text, status text, branch_id text references branches(id)
);
alter table appointments enable row level security;
create policy "appointments: view" on appointments for select using (clinic_id = my_clinic_id() and has_permission('appointments.view'));
create policy "appointments: insert" on appointments for insert with check (clinic_id = my_clinic_id() and has_permission('appointments.edit'));
create policy "appointments: update" on appointments for update using (clinic_id = my_clinic_id() and has_permission('appointments.edit'));
create policy "appointments: delete" on appointments for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));

create table if not exists consultations (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  date date, therapist text, dx text,
  -- The consultation form captures far more fields than first assumed (mode,
  -- problem/stg/ltg, onset/painsite/aggr/reliev, palp/gait/posture, meds,
  -- pastPhysio/pastSame/pastDiff, an upload-mode assessFile, etc.) — kept as
  -- one jsonb column rather than ~25 individual ones so nothing gets silently
  -- dropped; `date`/`therapist`/`dx` stay real columns since the consultations
  -- list view sorts/displays by them directly.
  data jsonb not null default '{}'::jsonb
);
alter table consultations enable row level security;
create policy "consultations: view" on consultations for select using (clinic_id = my_clinic_id() and has_permission('clinical.view'));
create policy "consultations: write" on consultations for all
  using (clinic_id = my_clinic_id() and has_permission('clinical.edit'))
  with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));

create table if not exists assessments (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  date date, therapist text, dx text,
  -- Same reasoning as consultations: the assessment form builds up a much
  -- richer object than first assumed (regions/obs/palp/neuro/rom/mmt/tests,
  -- homeLinks, assessFile/assessFilePath for the upload-mode scan, etc.) —
  -- date/therapist/dx stay real columns since the assessment list sorts and
  -- displays by them; everything else lives in `data` so nothing gets
  -- silently dropped.
  data jsonb not null default '{}'::jsonb
);
alter table assessments enable row level security;
create policy "assessments: view" on assessments for select using (clinic_id = my_clinic_id() and has_permission('clinical.view'));
create policy "assessments: insert" on assessments for insert with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "assessments: update" on assessments for update using (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "assessments: delete" on assessments for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));

create table if not exists treatment_plans (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  diagnosis text, goal text, sessions int, done int not null default 0,
  modalities jsonb default '[]'::jsonb, exercises jsonb default '[]'::jsonb, home jsonb default '[]'::jsonb,
  home_freq text, notes text, home_links jsonb default '[]'::jsonb,
  visits jsonb not null default '[]'::jsonb -- session log array; sub-visits don't need their own RLS row
);
alter table treatment_plans enable row level security;
create policy "treatment_plans: view" on treatment_plans for select using (clinic_id = my_clinic_id() and has_permission('clinical.view'));
create policy "treatment_plans: insert" on treatment_plans for insert with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "treatment_plans: update" on treatment_plans for update using (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "treatment_plans: delete" on treatment_plans for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));
-- Note: removing one logged session from a plan's `visits` jsonb array (delSession in
-- the app) is a row UPDATE, not a DELETE — governed by clinical.edit above, same as
-- everything else in that column. The original app also gated delSession as
-- owner-only in the UI; that specific extra restriction is not reproduced at the DB
-- level here (would need a trigger diffing old/new visits, disproportionate for one
-- sub-field) — flagged in HANDOFF.md.

create table if not exists package_templates (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  name text not null, sessions int, price numeric, validity int
);
alter table package_templates enable row level security;
create policy "package_templates: view" on package_templates for select using (clinic_id = my_clinic_id() and has_permission('billing.view'));
create policy "package_templates: write" on package_templates for all
  using (clinic_id = my_clinic_id() and has_permission('billing.edit'))
  with check (clinic_id = my_clinic_id() and has_permission('billing.edit'));

create table if not exists patient_packages (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  package_name text, total int, used int not null default 0, price numeric, paid_amount numeric,
  bought date, expires date, status text
);
alter table patient_packages enable row level security;
create policy "patient_packages: view" on patient_packages for select using (clinic_id = my_clinic_id() and has_permission('billing.view'));
create policy "patient_packages: insert" on patient_packages for insert with check (clinic_id = my_clinic_id() and has_permission('billing.edit'));
create policy "patient_packages: update" on patient_packages for update using (clinic_id = my_clinic_id() and has_permission('billing.edit'));
create policy "patient_packages: delete" on patient_packages for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));

create table if not exists invoices (
  id text primary key, -- keeps human-readable ids like 'INV-2026-041'
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  date date, status text, mode text, branch_id text references branches(id),
  items jsonb not null default '[]'::jsonb, gst numeric not null default 0,
  -- Invoices pick up a lot of optional fields depending on how they were paid
  -- (splitPayments, discount, note, paid/pending, corp, type, paidAt, an
  -- explicit total override) — same reasoning as consultations: named columns
  -- only for what's actually filtered/sorted/displayed (date/status/mode/
  -- branch/items/gst), everything else in this catch-all so nothing surprising
  -- gets silently dropped.
  data jsonb not null default '{}'::jsonb
);
alter table invoices enable row level security;
create policy "invoices: view" on invoices for select using (clinic_id = my_clinic_id() and has_permission('billing.view'));
create policy "invoices: insert" on invoices for insert with check (clinic_id = my_clinic_id() and has_permission('billing.edit'));
create policy "invoices: update" on invoices for update using (clinic_id = my_clinic_id() and has_permission('billing.edit'));
create policy "invoices: delete" on invoices for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));

create table if not exists expenses (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  date date, time text, category text, amount numeric, note text,
  bill_name text, bill_path text, bill_type text, -- bill_name: original filename shown in the UI; bill_path: storage object path for the signed-URL fetch
  branch_id text references branches(id)
);
alter table expenses enable row level security;
create policy "expenses: view" on expenses for select using (clinic_id = my_clinic_id() and has_permission('expenses.view'));
create policy "expenses: insert" on expenses for insert with check (clinic_id = my_clinic_id() and has_permission('expenses.edit'));
create policy "expenses: update" on expenses for update using (clinic_id = my_clinic_id() and has_permission('expenses.edit'));
create policy "expenses: delete" on expenses for delete using (clinic_id = my_clinic_id() and has_permission('records.delete'));

create table if not exists reminders (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text references patients(id) on delete cascade,
  -- `when` in the app is a display string ("Sent 15 Aug 2026"), not a real
  -- timestamp — originally typed timestamptz here, which would have
  -- rejected every insert. `sent_at` is the actual ISO date alongside it.
  channel text, kind text, when_text text, appt_label text, status text, sent_at date
);
alter table reminders enable row level security;
create policy "reminders: view" on reminders for select using (clinic_id = my_clinic_id() and has_permission('reminders.view'));
create policy "reminders: write" on reminders for all
  using (clinic_id = my_clinic_id() and has_permission('reminders.edit'))
  with check (clinic_id = my_clinic_id() and has_permission('reminders.edit'));

create table if not exists message_templates (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  category text, tag text, icon text, label text, msg text
);
alter table message_templates enable row level security;
create policy "message_templates: view" on message_templates for select using (clinic_id = my_clinic_id() and has_permission('reminders.view'));
create policy "message_templates: write" on message_templates for all
  using (clinic_id = my_clinic_id() and has_permission('reminders.edit'))
  with check (clinic_id = my_clinic_id() and has_permission('reminders.edit'));

create table if not exists staff (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  name text, job_title text, phone text, branch_id text references branches(id),
  salary numeric, present int, leave int,
  -- Vestigial: a pre-RBAC "admin/therapist/reception" access dropdown that the
  -- new roles/permissions system has superseded — nothing reads it for actual
  -- authorization anymore, but it's kept so the field still round-trips.
  access text
);
alter table staff enable row level security;
create policy "staff: view" on staff for select using (clinic_id = my_clinic_id() and has_permission('staff.manage'));
create policy "staff: write" on staff for all
  using (clinic_id = my_clinic_id() and has_permission('staff.manage'))
  with check (clinic_id = my_clinic_id() and has_permission('staff.manage'));

-- Confirmed shape: staff_id + date + a single status field (Present/Leave/etc.)
create table if not exists attendance (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  staff_id text references staff(id) on delete cascade,
  date date, status text
);
alter table attendance enable row level security;
create policy "attendance: view" on attendance for select using (clinic_id = my_clinic_id() and has_permission('staff.manage'));
create policy "attendance: write" on attendance for all
  using (clinic_id = my_clinic_id() and has_permission('staff.manage'))
  with check (clinic_id = my_clinic_id() and has_permission('staff.manage'));

create table if not exists clinic_settings (
  clinic_id uuid primary key references clinics(id) on delete cascade,
  wa boolean not null default true, sms boolean not null default true,
  lead_hrs int not null default 24, pay_reminder boolean not null default true,
  clinic_name text not null default '', gstin text not null default '', msg_credits int not null default 0
);
alter table clinic_settings enable row level security;
create policy "clinic_settings: view" on clinic_settings for select using (clinic_id = my_clinic_id());
create policy "clinic_settings: write" on clinic_settings for all
  using (clinic_id = my_clinic_id() and has_permission('settings.manage'))
  with check (clinic_id = my_clinic_id() and has_permission('settings.manage'));

create table if not exists audit_log (
  id text primary key default gen_random_uuid()::text,
  clinic_id uuid not null references clinics(id) on delete cascade,
  actor_name text, action text, detail text, patient text, created_at timestamptz not null default now()
);
alter table audit_log enable row level security;
create policy "audit_log: view" on audit_log for select using (clinic_id = my_clinic_id() and has_permission('audit.view'));
create policy "audit_log: insert" on audit_log for insert with check (clinic_id = my_clinic_id()); -- any clinic member can log an action

-- Reference/config lists (exercise link library, preset library, custom
-- modality names, billing service price list). Exact shapes weren't
-- visible from the source app beyond "currently empty arrays" — kept as
-- a generic label+payload row so nothing is lost on round-trip; tighten
-- the columns once the real shape is confirmed against the live app.
create table if not exists exercise_links (
  id text primary key default gen_random_uuid()::text, clinic_id uuid not null references clinics(id) on delete cascade,
  name text, link text
);
create table if not exists exercise_presets (
  id text primary key default gen_random_uuid()::text, clinic_id uuid not null references clinics(id) on delete cascade,
  label text, data jsonb not null default '{}'::jsonb
);
create table if not exists custom_modalities (
  id text primary key default gen_random_uuid()::text, clinic_id uuid not null references clinics(id) on delete cascade,
  name text
);
create table if not exists billing_services (
  id text primary key default gen_random_uuid()::text, clinic_id uuid not null references clinics(id) on delete cascade,
  name text, rate numeric
);
alter table exercise_links enable row level security;
alter table exercise_presets enable row level security;
alter table custom_modalities enable row level security;
alter table billing_services enable row level security;
create policy "exercise_links: view" on exercise_links for select using (clinic_id = my_clinic_id());
create policy "exercise_links: write" on exercise_links for all using (clinic_id = my_clinic_id() and has_permission('clinical.edit')) with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "exercise_presets: view" on exercise_presets for select using (clinic_id = my_clinic_id());
create policy "exercise_presets: write" on exercise_presets for all using (clinic_id = my_clinic_id() and has_permission('clinical.edit')) with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "custom_modalities: view" on custom_modalities for select using (clinic_id = my_clinic_id());
create policy "custom_modalities: write" on custom_modalities for all using (clinic_id = my_clinic_id() and has_permission('clinical.edit')) with check (clinic_id = my_clinic_id() and has_permission('clinical.edit'));
create policy "billing_services: view" on billing_services for select using (clinic_id = my_clinic_id());
create policy "billing_services: write" on billing_services for all using (clinic_id = my_clinic_id() and has_permission('billing.edit')) with check (clinic_id = my_clinic_id() and has_permission('billing.edit'));

create table if not exists active_sessions (
  clinic_id uuid not null references clinics(id) on delete cascade,
  patient_id text not null references patients(id) on delete cascade,
  primary key(clinic_id, patient_id)
);
alter table active_sessions enable row level security;
create policy "active_sessions: view" on active_sessions for select using (clinic_id = my_clinic_id() and has_permission('appointments.view'));
create policy "active_sessions: write" on active_sessions for all
  using (clinic_id = my_clinic_id() and has_permission('appointments.edit'))
  with check (clinic_id = my_clinic_id() and has_permission('appointments.edit'));

-- ── 5. Backfill for clinics created under migration 1 ──────────
-- Run once. Creates default Owner/Therapist/Receptionist roles for any
-- clinic that doesn't have roles yet, links existing profiles to them
-- by their old `role` text column, and unpacks each clinic's clinic_data
-- JSON blob into the new tables. UNTESTED against real data (no clinics
-- existed to test against at the time this was written) — dry-run on a
-- copy of the database first if any clinic has real data in it.
do $$
declare
  c record; owner_id uuid; therapist_id uuid; receptionist_id uuid;
  blob jsonb; branch_map jsonb; patient_map jsonb;
begin
  for c in select id from clinics loop
    if not exists (select 1 from roles where clinic_id = c.id) then
      insert into roles(clinic_id,name,is_owner_role,permissions) values
        (c.id,'Owner',true,(select jsonb_object_agg(key,true) from permission_catalog))
        returning id into owner_id;
      insert into roles(clinic_id,name,is_owner_role,permissions) values
        (c.id,'Therapist',false,'{"patients.view":true,"patients.edit":true,"clinical.view":true,"clinical.edit":true,"appointments.view":true,"appointments.edit":true,"reminders.view":true}'::jsonb)
        returning id into therapist_id;
      insert into roles(clinic_id,name,is_owner_role,permissions) values
        (c.id,'Receptionist',false,'{"patients.view":true,"patients.edit":true,"appointments.view":true,"appointments.edit":true,"billing.view":true,"billing.edit":true,"reminders.view":true,"reminders.edit":true}'::jsonb)
        returning id into receptionist_id;
      update profiles set role_id = case role
          when 'owner' then owner_id when 'therapist' then therapist_id else receptionist_id end
        where clinic_id = c.id and role_id is null;
    end if;

    select data into blob from clinic_data where clinic_id = c.id;
    continue when blob is null;

    -- branches first (other tables reference branch_id)
    -- Identity maps (old blob id -> same id, as text) — not a remap. Kept as a jsonb
    -- lookup only so the rest of this block can stay written the same shape as a real
    -- remap would need, in case a future edit changes patients/branches back to uuid.
    select jsonb_object_agg(b->>'id', b->>'id') into branch_map
      from jsonb_array_elements(coalesce(blob->'branches','[]'::jsonb)) b;
    insert into branches(id,clinic_id,name,address,phone)
      select b->>'id', c.id, b->>'name', b->>'address', b->>'phone'
      from jsonb_array_elements(coalesce(blob->'branches','[]'::jsonb)) b
      on conflict (id) do nothing;

    select jsonb_object_agg(p->>'id', p->>'id') into patient_map
      from jsonb_array_elements(coalesce(blob->'patients','[]'::jsonb)) p;
    insert into patients(id,clinic_id,name,dob,age,gender,phone,condition,since,since_time,therapist,branch_id,wallet,status,email,occ,addr,em_name,em_phone,ref_dr,docs)
      select p->>'id', c.id, p->>'name', nullif(p->>'dob','')::date, nullif(p->>'age','')::int, p->>'gender', p->>'phone',
        p->>'condition', nullif(p->>'since','')::date, p->>'sinceTime', p->>'therapist', nullif(branch_map->>(p->>'branch'),''),
        coalesce((p->>'wallet')::numeric,0), coalesce(p->>'status','Active'), p->>'email', p->>'occ', p->>'addr',
        p->>'emName', p->>'emPhone', p->>'refDr', coalesce(p->'docs','[]'::jsonb)
      from jsonb_array_elements(coalesce(blob->'patients','[]'::jsonb)) p
      on conflict (id) do nothing;

    insert into appointments(clinic_id,patient_id,date,time,type,therapist,status,branch_id)
      select c.id, (patient_map->>(a->>'pid')), nullif(a->>'date','')::date, a->>'time', a->>'type', a->>'therapist', a->>'status', nullif(branch_map->>(a->>'branch'),'')
      from jsonb_array_elements(coalesce(blob->'appointments','[]'::jsonb)) a;

    insert into consultations(clinic_id,patient_id,date,therapist,dx,data)
      select c.id, (patient_map->>(x->>'pid')), nullif(x->>'date','')::date, x->>'therapist', x->>'dx', (x - 'id' - 'pid' - 'date' - 'therapist' - 'dx')
      from jsonb_array_elements(coalesce(blob->'consultations','[]'::jsonb)) x;

    insert into assessments(clinic_id,patient_id,date,therapist,dx,data)
      select c.id, (patient_map->>(x->>'pid')), nullif(x->>'date','')::date, x->>'therapist', x->>'dx', (x - 'id' - 'pid' - 'date' - 'therapist' - 'dx')
      from jsonb_array_elements(coalesce(blob->'assessments','[]'::jsonb)) x;

    insert into treatment_plans(clinic_id,patient_id,diagnosis,goal,sessions,done,modalities,exercises,home,home_freq,notes,home_links,visits)
      select c.id, (patient_map->>(x->>'pid')), x->>'diagnosis', x->>'goal', nullif(x->>'sessions','')::int, coalesce((x->>'done')::int,0),
        coalesce(x->'modalities','[]'::jsonb), coalesce(x->'exercises','[]'::jsonb), coalesce(x->'home','[]'::jsonb), x->>'homeFreq', x->>'notes',
        coalesce(x->'homeLinks','[]'::jsonb), coalesce(x->'visits','[]'::jsonb)
      from jsonb_array_elements(coalesce(blob->'plans','[]'::jsonb)) x;

    insert into package_templates(clinic_id,name,sessions,price,validity)
      select c.id, x->>'name', nullif(x->>'sessions','')::int, nullif(x->>'price','')::numeric, nullif(x->>'validity','')::int
      from jsonb_array_elements(coalesce(blob->'pkgTemplates','[]'::jsonb)) x;

    insert into patient_packages(clinic_id,patient_id,package_name,total,used,price,paid_amount,bought,expires,status)
      select c.id, (patient_map->>(x->>'pid')), x->>'pkg', nullif(x->>'total','')::int, coalesce((x->>'used')::int,0),
        nullif(x->>'price','')::numeric, nullif(x->>'paidAmount','')::numeric, nullif(x->>'bought','')::date, nullif(x->>'expires','')::date, x->>'status'
      from jsonb_array_elements(coalesce(blob->'patientPkgs','[]'::jsonb)) x;

    insert into invoices(id,clinic_id,patient_id,date,items,gst,status,mode,branch_id,data)
      select x->>'id', c.id, (patient_map->>(x->>'pid')), nullif(x->>'date','')::date, coalesce(x->'items','[]'::jsonb),
        coalesce(nullif(x->>'gst','')::numeric,0), x->>'status', x->>'mode', nullif(branch_map->>(x->>'branch'),''),
        (x - 'id' - 'pid' - 'date' - 'items' - 'gst' - 'status' - 'mode' - 'branch')
      from jsonb_array_elements(coalesce(blob->'invoices','[]'::jsonb)) x
      on conflict do nothing;

    insert into expenses(clinic_id,date,time,category,amount,note,bill_name,bill_path,bill_type,branch_id)
      select c.id, nullif(x->>'date','')::date, x->>'time', x->>'cat', nullif(x->>'amount','')::numeric, x->>'note',
        x->>'bill', nullif(x->>'billPath',''), x->>'billType', nullif(branch_map->>(x->>'branch'),'')
      from jsonb_array_elements(coalesce(blob->'expenses','[]'::jsonb)) x;

    insert into reminders(clinic_id,patient_id,channel,kind,when_text,appt_label,status,sent_at)
      select c.id, (patient_map->>(x->>'pid')), x->>'channel', x->>'kind', x->>'when', x->>'appt', x->>'status', nullif(x->>'sentAt','')::date
      from jsonb_array_elements(coalesce(blob->'reminders','[]'::jsonb)) x;

    insert into message_templates(clinic_id,category,tag,icon,label,msg)
      select c.id, x->>'category', x->>'tag', x->>'icon', x->>'label', x->>'msg'
      from jsonb_array_elements(coalesce(blob->'msgTemplates','[]'::jsonb)) x;

    insert into staff(clinic_id,name,job_title,phone,branch_id,salary,present,leave,access)
      select c.id, x->>'name', x->>'role', x->>'phone', nullif(branch_map->>(x->>'branch'),''),
        nullif(x->>'salary','')::numeric, nullif(x->>'present','')::int, nullif(x->>'leave','')::int, x->>'access'
      from jsonb_array_elements(coalesce(blob->'staff','[]'::jsonb)) x;

    insert into attendance(clinic_id,staff_id,date,status)
      select c.id, x->>'sid', nullif(x->>'date','')::date, x->>'status'
      from jsonb_array_elements(coalesce(blob->'attendance','[]'::jsonb)) x;

    insert into audit_log(clinic_id,actor_name,action,detail,patient,created_at)
      select c.id, x->>'user', x->>'action', x->>'detail', x->>'patient', coalesce(nullif(x->>'ts','')::timestamptz, now())
      from jsonb_array_elements(coalesce(blob->'auditLog','[]'::jsonb)) x;

    insert into clinic_settings(clinic_id,wa,sms,lead_hrs,pay_reminder,clinic_name,gstin,msg_credits)
      values (c.id, coalesce((blob->'settings'->>'wa')::boolean,true), coalesce((blob->'settings'->>'sms')::boolean,true),
        coalesce((blob->'settings'->>'leadHrs')::int,24), coalesce((blob->'settings'->>'payReminder')::boolean,true),
        coalesce(blob->'settings'->>'clinic',''), coalesce(blob->'settings'->>'gstin',''), coalesce((blob->'settings'->>'msgCredits')::int,0))
      on conflict (clinic_id) do nothing;

    insert into active_sessions(clinic_id,patient_id)
      select c.id, (patient_map->>(x.value)) from jsonb_array_elements_text(coalesce(blob->'active','[]'::jsonb)) x
      on conflict do nothing;
  end loop;
end $$;

commit;
