import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return Response.json({ error: "POST required" }, { status: 405, headers: cors });

  // Supabase Edge runs behind Cloudflare. Trust only its connecting-IP header.
  // Never use a client-supplied X-Forwarded-For value.
  const ip = (req.headers.get("cf-connecting-ip") || "").trim();
  if (!ip || ip.length > 64) {
    return Response.json({ allowed: true, checked: false }, { headers: cors });
  }

  let body: { session_id?: string } = {};
  try { body = await req.json(); } catch { /* check-only request */ }

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!serviceKey) return Response.json({ error: "Server configuration error" }, { status: 500, headers: cors });

  const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await db.rpc("nl_ip_is_restricted", { p_ip: ip });
  if (error) {
    console.error("IP restriction lookup failed", error.message);
    return Response.json({ error: "IP check unavailable" }, { status: 503, headers: cors });
  }
  if (data === true) return Response.json({ allowed: false, reason: "ip_restricted" }, { status: 403, headers: cors });

  // Attach a short fingerprint to an existing heartbeat; raw IP is not stored.
  const sessionId = body.session_id;
  if (typeof sessionId === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip.toLowerCase()));
    const fingerprint = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
    const { error: updateError } = await db.from("nl_live_visitors")
      .update({ ip_digest: fingerprint })
      .eq("session_id", sessionId);
    if (updateError) console.error("Could not attach visitor IP fingerprint", updateError.message);
  }

  return Response.json({ allowed: true, checked: true }, { headers: cors });
});