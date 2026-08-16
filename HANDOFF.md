# PhysioVerse multi-tenant migration — where things stand

## Deploy order (fresh project)

1. **`migration-1-multitenant.sql`**
2. **`migration-2-rbac-normalize.sql`** — includes the corrected assessments
   schema now, so a fresh install never hits the bug described below.
3. **`migration-3-billing-gate.sql`**
4. **`manage-staff`**, **`razorpay-create-subscription`**,
   **`razorpay-webhook`** (`--no-verify-jwt` on the last one)
5. **`physioverse-multitenant.html`** — paste Supabase URL/anon key in.

## If migration-2 already ran (your case — physiomind software)

Also run **`migration-4-fix-assessments.sql`** once. migration-2's original
assessments table guessed ~30 columns before checking real field usage —
same mistake caught for consultations/invoices, just missed this one at
the time. No real data at risk (test-only), so this just drops the wrong
columns and adds the right ones.

## Fully normalized now — every original blob resource is done

Patients, branches, consultations, expenses, appointments, invoices,
package templates, patient packages, staff, attendance, reminders, audit
log, and as of this pass: **assessments and treatment plans.**

- **Treatment plans** — schema was already correct (verified against every
  real call site first, learned that lesson). 7 mutation sites: plan create/
  edit, delete, session log create/edit, session delete, and the
  auto-create-plan-from-assessment flow (2 sub-cases: new plan, or syncing
  home-exercise links onto an existing one).
- **Assessments** — schema was wrong (confirmed via audit: real usage has
  `homeLinks`, `assessFile`, `assessFilePath` that didn't exist as columns,
  on top of already looking like a repeat of the consultations mistake).
  Collapsed to `date`/`therapist`/`dx` as real columns + a `data` jsonb
  catch-all, same pattern as consultations/invoices. `update()` takes the
  whole current object rather than a patch, matching invoices' reasoning —
  the assessment form rebuilds the full object on edit, not a partial diff.

**Every resource that started in the shared `clinic_data` blob has now
moved to its own RLS'd table.** RLS enforcement (`has_permission()`,
subscription gate) applies uniformly across all of them — no remaining gap
where a receptionist's browser could reach clinical or financial data via
a direct API call that the UI wouldn't show them.

## Still separately queued (unrelated to the normalization work)

- **Storage isolation** — done (clinic_id-prefixed paths), from a few
  passes back.
- **Billing gate** — built (Razorpay), not yet deployed/tested end-to-end
  with a real payment.
- **Pilot** — first real signup test surfaced 3 real bugs (wrong Supabase
  project deployed, email confirmation blocking signup, empty permissions
  on new accounts) — all fixed, but only tested once. Test again from a
  clean signup, and specifically confirm two separate clinics can't see
  each other's data — that check hasn't actually happened yet.
