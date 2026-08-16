// Supabase Edge Function: razorpay-webhook
// Deploy: supabase functions deploy razorpay-webhook --no-verify-jwt
//
// Public endpoint (no Supabase auth — Razorpay calls this directly), so it
// must be deployed with --no-verify-jwt. Authenticity instead comes from
// verifying Razorpay's own HMAC-SHA256 signature on the raw request body.
//
// Configure in Razorpay Dashboard → Settings → Webhooks:
//   URL: https://<project-ref>.supabase.co/functions/v1/razorpay-webhook
//   Secret: any string you choose — put the same value in the
//           RAZORPAY_WEBHOOK_SECRET Edge Function secret below
//   Events: subscription.activated, subscription.charged,
//           subscription.completed, subscription.cancelled,
//           subscription.halted, subscription.pending
//
// Needs these Edge Function secrets set (Project Settings → Edge Functions):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RAZORPAY_WEBHOOK_SECRET

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const RAZORPAY_WEBHOOK_SECRET = Deno.env.get("RAZORPAY_WEBHOOK_SECRET")!;

async function verifySignature(rawBody: string, signature: string): Promise<boolean> {
  if (!signature) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(RAZORPAY_WEBHOOK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(rawBody));
  const expected = Array.from(new Uint8Array(sigBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

// Maps a Razorpay subscription lifecycle event to the status/period-end this
// app tracks. Anything not listed here is acknowledged (200 OK, so Razorpay
// doesn't retry) but doesn't change subscription state — e.g. payment.failed
// on its own isn't acted on directly; Razorpay moves the subscription to
// 'halted' after its own retry cycle exhausts, which IS handled below.
function statusForEvent(event: string): string | null {
  switch (event) {
    case "subscription.activated":
    case "subscription.charged":
      return "active";
    case "subscription.completed":
    case "subscription.cancelled":
      return "canceled";
    case "subscription.halted":
      return "past_due";
    case "subscription.pending":
      return "past_due";
    default:
      return null;
  }
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("POST only", { status: 405 });

  const rawBody = await req.text();
  const signature = req.headers.get("X-Razorpay-Signature") || "";
  if (!(await verifySignature(rawBody, signature))) {
    return new Response("Invalid signature", { status: 401 });
  }

  let body: any;
  try {
    body = JSON.parse(rawBody);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const event = body?.event as string;
  const subEntity = body?.payload?.subscription?.entity;
  const newStatus = statusForEvent(event);

  // No subscription entity on this event, or an event type we don't act on —
  // acknowledge so Razorpay stops retrying, but nothing to update.
  if (!subEntity?.id || !newStatus) return new Response("ok", { status: 200 });

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
  const currentPeriodEnd = subEntity.current_end ? new Date(subEntity.current_end * 1000).toISOString() : null;

  const { error } = await admin
    .from("clinic_subscriptions")
    .update({ status: newStatus, current_period_end: currentPeriodEnd, updated_at: new Date().toISOString() })
    .eq("razorpay_subscription_id", subEntity.id);

  if (error) {
    // Log server-side for later investigation, but still 200 — a DB hiccup on
    // our end shouldn't make Razorpay hammer this endpoint with retries for
    // an event it already delivered successfully.
    console.error("Failed to update clinic_subscriptions:", error.message, "for razorpay subscription", subEntity.id);
  }

  return new Response("ok", { status: 200 });
});
