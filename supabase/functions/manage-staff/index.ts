// Supabase Edge Function: manage-staff (v2 — custom roles/permissions)
// Deploy: supabase functions deploy manage-staff
//
// Same job as v1 (invite/remove/reset-password for staff logins), but
// authorization now checks the caller's *permission* (staff.manage) via
// the roles/permissions system from migration-2, instead of a hardcoded
// role === 'owner' string — so a clinic that creates a custom "Clinic
// Manager" role with staff.manage can also invite staff, not just Owner.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const authHeader = req.headers.get("Authorization") || "";
  const callerToken = authHeader.replace(/^Bearer\s+/i, "");
  if (!callerToken) return json({ error: "Missing Authorization bearer token" }, 401);

  const asCaller = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    global: { headers: { Authorization: `Bearer ${callerToken}` } },
  });
  const { data: callerUser, error: callerErr } = await asCaller.auth.getUser();
  if (callerErr || !callerUser?.user) return json({ error: "Invalid session — sign in again" }, 401);

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  const { data: callerProfile, error: profileErr } = await admin
    .from("profiles")
    .select("clinic_id, role_id, roles(permissions)")
    .eq("user_id", callerUser.user.id)
    .maybeSingle();
  if (profileErr || !callerProfile) return json({ error: "No clinic profile found for this login" }, 403);

  const callerPerms = (callerProfile as any).roles?.permissions || {};
  if (!callerPerms["staff.manage"]) return json({ error: "You don't have permission to manage staff" }, 403);

  const clinicId = callerProfile.clinic_id;
  const body = await req.json().catch(() => ({}));
  const action = body.action as string;

  try {
    if (action === "invite") {
      const email = String(body.email || "").trim().toLowerCase();
      const name = String(body.name || "").trim();
      const roleId = String(body.role_id || "");
      const tempPassword = String(body.tempPassword || "");
      if (!email || !name) return json({ error: "Name and email are required" }, 400);
      if (!tempPassword || tempPassword.length < 6) return json({ error: "Temporary password must be at least 6 characters" }, 400);

      const { data: role, error: roleErr } = await admin
        .from("roles").select("id, clinic_id, is_owner_role").eq("id", roleId).maybeSingle();
      if (roleErr || !role || role.clinic_id !== clinicId) return json({ error: "Invalid role for this clinic" }, 400);
      if (role.is_owner_role) return json({ error: "Can't invite someone directly as Owner — transfer ownership separately" }, 400);

      const { data: created, error: createErr } = await admin.auth.admin.createUser({
        email, password: tempPassword, email_confirm: true,
      });
      if (createErr) return json({ error: createErr.message }, 400);

      const { error: insertErr } = await admin.from("profiles").insert({
        user_id: created.user!.id, clinic_id: clinicId, role_id: roleId, role: "receptionist", name, email,
        // `role` text kept only for backward-compat reads during the migration window; role_id is authoritative.
      });
      if (insertErr) {
        await admin.auth.admin.deleteUser(created.user!.id);
        return json({ error: insertErr.message }, 400);
      }
      return json({ ok: true, user_id: created.user!.id });
    }

    if (action === "reset-password") {
      const targetUserId = String(body.user_id || "");
      const newPassword = String(body.newPassword || "");
      if (!newPassword || newPassword.length < 6) return json({ error: "Password must be at least 6 characters" }, 400);

      const { data: targetProfile } = await admin.from("profiles").select("clinic_id").eq("user_id", targetUserId).maybeSingle();
      if (!targetProfile || targetProfile.clinic_id !== clinicId) return json({ error: "That login isn't part of your clinic" }, 403);

      const { error } = await admin.auth.admin.updateUserById(targetUserId, { password: newPassword });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    if (action === "remove") {
      const targetUserId = String(body.user_id || "");
      const { data: targetProfile } = await admin.from("profiles").select("clinic_id, roles(is_owner_role)").eq("user_id", targetUserId).maybeSingle();
      if (!targetProfile || targetProfile.clinic_id !== clinicId) return json({ error: "That login isn't part of your clinic" }, 403);
      if ((targetProfile as any).roles?.is_owner_role) return json({ error: "Can't remove the clinic owner" }, 400);

      await admin.from("profiles").delete().eq("user_id", targetUserId);
      const { error } = await admin.auth.admin.deleteUser(targetUserId);
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    return json({ error: "Unknown action" }, 400);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
