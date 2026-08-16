-- ═══════════════════════════════════════════════════════════════
-- PhysioVerse multi-tenant migration
-- Run this in Supabase SQL Editor (Database → SQL Editor → New query)
-- on a project that DOES NOT already have a clinic_data table shaped
-- like {id:'main', data:jsonb} — if it does, back it up first, this
-- migration replaces that table's shape.
-- ═══════════════════════════════════════════════════════════════

-- ── 1. Core tables ────────────────────────────────────────────
create table if not exists clinics (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  clinic_id uuid not null references clinics(id) on delete cascade,
  role text not null check (role in ('owner','therapist','receptionist')),
  name text not null default '',
  email text not null default '',
  created_at timestamptz not null default now()
);
create index if not exists profiles_clinic_id_idx on profiles(clinic_id);

-- Replaces the old single-row clinic_data table (id='main').
-- One row per clinic instead of one row total.
drop table if exists clinic_data cascade;
create table clinic_data (
  clinic_id uuid primary key references clinics(id) on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

alter table clinics enable row level security;
alter table profiles enable row level security;
alter table clinic_data enable row level security;

-- ── 2. Helper functions ──────────────────────────────────────
-- security definer so these can read `profiles` even though the
-- caller's own RLS on `profiles` would otherwise block it (the
-- policies on `profiles` themselves call these functions).
create or replace function my_clinic_id()
returns uuid
language sql stable security definer set search_path = public
as $$ select clinic_id from profiles where user_id = auth.uid() $$;

create or replace function my_role()
returns text
language sql stable security definer set search_path = public
as $$ select role from profiles where user_id = auth.uid() $$;

-- ── 3. RLS policies ───────────────────────────────────────────
create policy "clinics: read own" on clinics for select
  using (id = my_clinic_id());

create policy "profiles: read clinicmates" on profiles for select
  using (clinic_id = my_clinic_id());
create policy "profiles: owner deletes clinicmates" on profiles for delete
  using (clinic_id = my_clinic_id() and my_role() = 'owner');
-- No client-side insert/update policy on profiles by design — staff
-- profiles are created/edited only by the manage-staff Edge Function
-- (using the service-role key), never directly from the browser.

create policy "clinic_data: read own clinic" on clinic_data for select
  using (clinic_id = my_clinic_id());
create policy "clinic_data: insert own clinic" on clinic_data for insert
  with check (clinic_id = my_clinic_id());
create policy "clinic_data: update own clinic" on clinic_data for update
  using (clinic_id = my_clinic_id());

-- ── 4. Signup bootstrap ───────────────────────────────────────
-- Called once, right after auth.signUp(), by a brand-new user who
-- has no profile yet. Creates their clinic + owner profile + empty
-- data row atomically. security definer so it can insert into
-- `profiles`/`clinics` despite the browser having no write policy
-- on those tables.
create or replace function create_clinic_and_owner(clinic_name text, owner_name text, owner_email text)
returns uuid
language plpgsql security definer set search_path = public
as $$
declare
  new_clinic_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Not signed in';
  end if;
  if exists (select 1 from profiles where user_id = auth.uid()) then
    raise exception 'This login is already linked to a clinic';
  end if;
  insert into clinics(name) values (trim(clinic_name)) returning id into new_clinic_id;
  insert into profiles(user_id, clinic_id, role, name, email)
    values (auth.uid(), new_clinic_id, 'owner', trim(owner_name), lower(trim(owner_email)));
  insert into clinic_data(clinic_id, data) values (new_clinic_id, '{}'::jsonb);
  return new_clinic_id;
end;
$$;
grant execute on function create_clinic_and_owner(text,text,text) to authenticated;

-- ── 5. Storage isolation (patient docs, bill photos, assessment PDFs) ──
-- Every upload/read under these three buckets is prefixed with
-- `${CLINIC_ID}/...` (first path segment = the clinic's id) in the app —
-- patient-documents and bill-photos uploads, and assessment-pdfs uploads
-- for both scanned images and generated PDFs. Everywhere else in the app
-- reads whatever path was already stored on the record (a patient's doc
-- entry, an expense's billPath), so once the upload side is prefixed
-- correctly those reads carry it through automatically — the only two
-- spots that needed their own fix were the assessment-PDF view/download
-- functions, which reconstruct the path from the assessment id rather
-- than reading a stored field.
create policy "storage: clinic reads own files" on storage.objects for select
  using (bucket_id in ('patient-documents','bill-photos','assessment-pdfs')
         and (storage.foldername(name))[1] = my_clinic_id()::text);
create policy "storage: clinic writes own files" on storage.objects for insert
  with check (bucket_id in ('patient-documents','bill-photos','assessment-pdfs')
         and (storage.foldername(name))[1] = my_clinic_id()::text);
create policy "storage: clinic deletes own files" on storage.objects for delete
  using (bucket_id in ('patient-documents','bill-photos','assessment-pdfs')
         and (storage.foldername(name))[1] = my_clinic_id()::text);

-- ── 6. (Optional, do later) billing gate ───────────────────────
-- create table clinic_subscriptions (
--   clinic_id uuid primary key references clinics(id) on delete cascade,
--   status text not null default 'trialing',  -- trialing | active | past_due | canceled
--   current_period_end timestamptz
-- );
-- Then add `and exists (select 1 from clinic_subscriptions s where s.clinic_id = my_clinic_id() and s.status in ('trialing','active'))`
-- to the clinic_data policies above once Stripe/Razorpay billing exists.
