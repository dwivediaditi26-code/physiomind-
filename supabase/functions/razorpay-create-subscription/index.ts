// Supabase Edge Function: razorpay-create-subscription
// Deploy: supabase functions deploy razorpay-create-subscription
//
// Called by the app when the clinic owner clicks "Subscribe". Creates a
// Razorpay Customer (if one doesn't exist yet for this clinic) and a
// Razorpay Subscription, stores both ids on clinic_subscriptions, and
// returns what the frontend needs to open Razorpay's Checkout modal
// (razorpay-checkout.js, using { subscription_id, key: RAZORPAY_KEY_ID }).
//
// Needs these Edge Function secrets set (Project Settings → Edge Functions):
//   RAZORPAY_KEY_ID       — from Razorpay Dashboard → Settings → API Keys
//   RAZORPAY_KEY_SECRET   — same page (server-side only, never sent to the app)
//   RAZORPAY_PLAN_ID      — create a Plan first: Dashboard → Subscriptions →
//                           Plans → New Plan (sets the price/billing interval)
//
// Deliberately owner-only (not staff.manage-delegable, unlike staff invites)
// — billing is treated the same way factoryReset() is in the app: a small
// set of actions that stay tied to the protected Owner role regardless of
// what a custom role's permissions say.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const RAZORPAY_KEY_ID = Deno.env.get("RAZORPAY_KEY_ID")!;
const RAZORPAY_KEY_SECRET = Deno.env.get("RAZORPAY_KEY_SECRET")!;
const RAZORPAY_PLAN_ID = Deno.env.get("RAZORPAY_PLAN_ID")!;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
}

async function razorpayFetch(path: string, options: RequestInit = {}) {
  const auth = btoa(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`);
  const res = await fetch(`https://api.razorpay.com/v1${path}`, {
    ...options,
    headers: { ...options.headers, Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.description || `Razorpay API error (${res.status})`);
  return data;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const callerToken = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!callerToken) return json({ error: "Missing Authorization bearer token" }, 401);

  const asCaller = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    global: { headers: { Authorization: `Bearer ${callerToken}` } },
  });
  const { data: callerUser, error: callerErr } = await asCaller.auth.getUser();
  if (callerErr || !callerUser?.user) return json({ error: "Invalid session — sign in again" }, 401);

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  const { data: profile, error: profileErr } = await admin
    .from("profiles")
    .select("clinic_id, name, email, roles(is_owner_role)")
    .eq("user_id", callerUser.user.id)
    .maybeSingle();
  if (profileErr || !profile) return json({ error: "No clinic profile found for this login" }, 403);
  if (!(profile as any).roles?.is_owner_role) return json({ error: "Only the clinic owner can manage billing" }, 403);

  const clinicId = profile.clinic_id;

  try {
    const { data: sub } = await admin
      .from("clinic_subscriptions")
      .select("razorpay_customer_id, razorpay_subscription_id, status")
      .eq("clinic_id", clinicId)
      .maybeSingle();

    if (sub?.razorpay_subscription_id && sub.status === "active") {
      return json({ error: "This clinic already has an active subscription." }, 400);
    }

    // Reuse the Razorpay customer if one was already created for a previous
    // (e.g. abandoned or lapsed) checkout attempt, otherwise create one.
    let customerId = sub?.razorpay_customer_id;
    if (!customerId) {
      const customer = await razorpayFetch("/customers", {
        method: "POST",
        body: JSON.stringify({ name: profile.name || "Clinic owner", email: profile.email, notes: { clinic_id: clinicId } }),
      });
      customerId = customer.id;
    }

    const subscription = await razorpayFetch("/subscriptions", {
      method: "POST",
      body: JSON.stringify({
        plan_id: RAZORPAY_PLAN_ID,
        customer_notify: 1,
        total_count: 1200, // effectively "until cancelled" — Razorpay subscriptions require a finite cycle count
        notes: { clinic_id: clinicId },
      }),
    });

    await admin.from("clinic_subscriptions").upsert({
      clinic_id: clinicId,
      razorpay_customer_id: customerId,
      razorpay_subscription_id: subscription.id,
      updated_at: new Date().toISOString(),
    });

    return json({ subscription_id: subscription.id, key_id: RAZORPAY_KEY_ID });
  } catch (e) {
    return json({ error: String(e instanceof Error ? e.message : e) }, 500);
  }
});
