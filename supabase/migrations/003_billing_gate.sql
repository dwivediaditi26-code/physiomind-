-- ═══════════════════════════════════════════════════════════════
-- PhysioVerse migration 3: billing gate (Razorpay)
-- Run after migration-1 and migration-2.
--
-- Design: rather than adding a subscription check to ~40 individual
-- policies, has_permission() — already the gate every real-data table's
-- RLS routes through (see migration-2) — now also requires an active
-- subscription. One function edit cascades everywhere automatically.
-- Left deliberately ungated: profiles/roles (read) and a few low-
-- sensitivity reference lists (branches, clinic_settings, exercise/
-- modality/billing reference data) — so a lapsed clinic can still sign
-- in, see who they are, and render a "please renew" screen, without any
-- real patient/clinical/financial data being reachable.
-- ═══════════════════════════════════════════════════════════════

-- ── 1. Subscription table ────────────────────────────────────────
create table if not exists clinic_subscriptions (
  clinic_id uuid primary key references clinics(id) on delete cascade,
  status text not null default 'trialing', -- trialing | active | past_due | canceled | halted
  current_period_end timestamptz,
  razorpay_customer_id text,
  razorpay_subscription_id text,
  updated_at timestamptz not null default now()
);
alter table clinic_subscriptions enable row level security;
-- Read-only from the browser (any clinic member, so the lockout screen can show
-- status/renewal date) — every write comes from the two Edge Functions below,
-- which use the service-role key and bypass RLS entirely.
create policy "clinic_subscriptions: read own clinic" on clinic_subscriptions for select
  using (clinic_id = my_clinic_id());

-- ── 2. Subscription check ────────────────────────────────────────
-- A short grace period on 'past_due' (Razorpay's own retry cycle typically
-- takes a few days) avoids hard-locking a clinic out the instant one charge
-- attempt fails, before Razorpay has finished retrying.
create or replace function has_active_subscription()
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists(
    select 1 from clinic_subscriptions s
    where s.clinic_id = my_clinic_id()
    and (
      s.status in ('trialing','active')
      or (s.status = 'past_due' and coalesce(s.current_period_end, now()) > now() - interval '3 days')
    )
  )
$$;

-- ── 3. Wire it into has_permission() ─────────────────────────────
create or replace function has_permission(perm text)
returns boolean
language sql stable security definer set search_path = public
as $$
  select has_active_subscription() and coalesce(
    (select (r.permissions->>perm)::boolean
     from profiles p join roles r on r.id = p.role_id
     where p.user_id = auth.uid()),
    false
  )
$$;

-- ── 4. Gate clinic_data directly ─────────────────────────────────
-- clinic_data predates has_permission() (migration-1) and still holds real
-- data (assessments, treatment plans, settings, reference lists not yet
-- normalized) — its own policies check clinic_id only, so the subscription
-- check needs adding here explicitly.
drop policy if exists "clinic_data: read own clinic" on clinic_data;
drop policy if exists "clinic_data: insert own clinic" on clinic_data;
drop policy if exists "clinic_data: update own clinic" on clinic_data;
create policy "clinic_data: read own clinic" on clinic_data for select
  using (clinic_id = my_clinic_id() and has_active_subscription());
create policy "clinic_data: insert own clinic" on clinic_data for insert
  with check (clinic_id = my_clinic_id() and has_active_subscription());
create policy "clinic_data: update own clinic" on clinic_data for update
  using (clinic_id = my_clinic_id() and has_active_subscription());

-- ── 5. Start every new signup on a trial ─────────────────────────
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
    (new_clinic_id,'Owner',true,(select jsonb_object_agg(key,true) from permission_catalog))
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
  insert into branches(id, clinic_id, name, address, phone) values (gen_random_uuid()::text, new_clinic_id, 'Main Branch', '', '');
  insert into clinic_data(clinic_id, data) values (new_clinic_id, jsonb_build_object(
    'exercisePresets','[]'::jsonb,'customModalities','[]'::jsonb,'billingServices','[]'::jsonb,'exerciseLinks','[]'::jsonb,
    'assessments','[]'::jsonb,'plans','[]'::jsonb,'msgTemplates','[]'::jsonb,'auditLog','[]'::jsonb,
    'settings',jsonb_build_object('wa',true,'sms',true,'leadHrs',24,'payReminder',true,'clinic',trim(clinic_name),'gstin','','msgCredits',0)
  ));
  -- 14-day trial, no card required. Change the interval below to adjust the length.
  insert into clinic_subscriptions(clinic_id, status, current_period_end)
    values (new_clinic_id, 'trialing', now() + interval '14 days');
  return new_clinic_id;
end;
$$;
grant execute on function create_clinic_and_owner(text,text,text) to authenticated;

-- ── 6. Backfill existing clinics ──────────────────────────────────
-- Any clinic created before this migration (realistically just the one
-- pilot clinic at this stage) gets grandfathered onto 'active' with no
-- expiry, rather than being retroactively locked out the moment this
-- migration runs, before Razorpay is even wired up. Revisit manually
-- once real billing starts.
insert into clinic_subscriptions(clinic_id, status, current_period_end)
  select id, 'active', null from clinics
  where id not in (select clinic_id from clinic_subscriptions)
on conflict (clinic_id) do nothing;
