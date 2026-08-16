# PhysioVerse multi-tenant migration — where things stand

## Deploy order

1. **`migration-1-multitenant.sql`** — clinics/profiles/clinic_data, RLS,
   storage isolation for the three document buckets.
2. **`migration-2-rbac-normalize.sql`** — permission system + normalized
   tables + per-permission RLS for every resource except assessments/
   treatment plans (still in the blob).
3. **`migration-3-billing-gate.sql`** — the billing gate (this pass).
4. **`manage-staff/index.ts`** — staff invite/reset/remove, authorizes via
   `staff.manage` permission.
5. **`razorpay-create-subscription/index.ts`** — deploy normally
   (`supabase functions deploy razorpay-create-subscription`).
6. **`razorpay-webhook/index.ts`** — deploy with
   `supabase functions deploy razorpay-webhook --no-verify-jwt` (public
   endpoint — Razorpay calls it directly, no Supabase session involved;
   authenticity comes from verifying Razorpay's signature instead).
7. **`physioverse-multitenant.html`** — paste Supabase URL/anon key at the
   top of the `<script>` tag.

## One-time Razorpay dashboard setup (can't be done from here)

- Create a Razorpay account, get **Key ID** and **Key Secret**
  (Settings → API Keys).
- Create a **Plan** (Subscriptions → Plans → New Plan) — this sets your
  price and billing interval (monthly/annual). Copy its `plan_id`.
- Create a **Webhook** (Settings → Webhooks) pointing at
  `https://<project-ref>.supabase.co/functions/v1/razorpay-webhook`,
  subscribed to: `subscription.activated`, `subscription.charged`,
  `subscription.completed`, `subscription.cancelled`,
  `subscription.halted`, `subscription.pending`. Pick a webhook secret —
  any string, it just has to match what you put in Supabase.
- Set these as Edge Function secrets (Project Settings → Edge Functions):
  `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_PLAN_ID`,
  `RAZORPAY_WEBHOOK_SECRET`.

## How the gate works

Rather than adding a subscription check to the ~40 individual RLS
policies migration-2 created, `has_permission()` — the function every
real-data table's policy already routes through — now also requires
`has_active_subscription()`. One function edit cascades everywhere: the
moment a clinic's subscription lapses, every patient/appointment/invoice/
staff read-or-write across the whole app is blocked at the database level,
automatically. `clinic_data` (still holding assessments/plans until those
are ported) got the same check added directly, since its policies predate
`has_permission()`.

Left deliberately **ungated**: reading `profiles`, `roles`, the branches
list, clinic settings, and the exercise/modality/billing reference lists.
That's on purpose — a lapsed clinic can still sign in and see who they
are, so the app can render the "please renew" screen instead of just
breaking. No real patient/clinical/financial data is reachable in that
state.

- New signups get a **14-day trial**, no card required (the interval is
  one line in `create_clinic_and_owner()` if you want to change it).
- A short **3-day grace period** on `past_due` avoids hard-locking a
  clinic out the instant one payment attempt fails, before Razorpay's own
  retry cycle has finished.
- **Existing clinics** (realistically just the one pilot clinic right
  now) get grandfathered onto `active` with no expiry by this migration's
  backfill, rather than retroactively locked out before Razorpay is even
  configured.

App side: a full-screen lockout overlay (owner sees a "Subscribe now"
button; everyone else sees "ask your clinic owner") plus a dismissible-
free trial-countdown banner, both driven by reading `clinic_subscriptions`
after login — which is safe to read even when locked out, since it's one
of the deliberately-ungated tables. If that read fails (network hiccup),
the UI fails **open** — no lockout shown — but real data access stays
exactly as protected either way, since RLS doesn't depend on this
client-side read at all.

## What I could not verify

Genuinely no way to test any of this without a live Supabase project and
a live Razorpay account — neither is reachable from here. I've reviewed
the Edge Functions and SQL as carefully as static review allows (brace/
paren balance, matching field names against what each API actually
returns, based on Razorpay's documented webhook payload shape), but
payment integrations are exactly the kind of thing that can have a subtle
bug that only surfaces against the real API. **Test the whole loop — sign
up a throwaway clinic, let the trial run out (or manually flip its status
in the DB to test the lockout faster), subscribe with a real Razorpay test-
mode card, confirm the webhook actually flips status to `active`** —
before pointing any of this at your friend's real clinic or a real
customer.

## Not done yet

- **Assessments, treatment plans** — the two resources still in the
  shared blob. Not blocking the billing gate (clinic_data's policies now
  cover them same as everything else), but still not permission-
  differentiated the way the rest of the app is.
- **Cancellation flow** — there's no in-app "cancel my subscription"
  button; right now that'd happen through Razorpay's own customer portal
  or dashboard, with the webhook picking up the resulting
  `subscription.cancelled` event.
- **Pilot** — the step every prior handoff note has ended on, now with
  one more thing to include: test signup → trial → invite → custom role →
  data isolation → document upload → **billing lockout and recovery** →
  end-to-end with 2–3 real clinics before opening signup publicly.
