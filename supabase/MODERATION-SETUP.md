# Nameless Labs moderation rollout

## 1. Apply the database migration

In Supabase Dashboard → SQL Editor, run the complete `supabase/moderation.sql` file after the existing `supabase/schema.sql`. It creates moderation state, live visitor heartbeats, IP restriction digests and an append-only audit trail.

All administrator RPCs verify `public.is_admin()` on the server. Do not add direct table write policies and never put the Supabase service-role key in browser code.

## 2. Open the console

After the migration is applied, sign in to the existing Supabase-backed admin dashboard and open **Moderation center**, or visit `/admin-namelesslabs/moderation.html`.

The moderation page intentionally refuses local/demo sessions. The browser role is not trusted for authorization; the RPC checks the authenticated Supabase user against `admin_roles`.

## 3. Show anonymous visitors

The public NamelessAI application must create a random UUID for each browser session and call `visitor_heartbeat` periodically (about every 30 seconds), passing the UUID, a display label and a short user-agent string. Stop heartbeats when the session ends. Check for an RPC error: a kicked session is rejected for 24 hours. Do not use IP addresses as visitor identity.

## 4. Enforce IP restrictions

Deploy `supabase/functions/ip-guard/index.ts` and call it from a trusted server-side request path before allowing traffic into the public app. Configure `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` as Edge Function secrets. The function reads the connecting IP from trusted proxy headers and checks the server-side SHA-256 digest. Ensure the hosting proxy overwrites incoming forwarding headers; never trust arbitrary client-supplied `X-Forwarded-For`.

This is an enforcement endpoint, not a transparent proxy. Your app/backend must invoke it for requests that need IP enforcement and reject the request when it returns HTTP 403 or 503. Do not call it directly from browser JavaScript.

## 5. Moderation semantics and safeguards

- Rank is an application rank stored in `user_moderation`; it does not grant Supabase admin-console access. Console access remains controlled by `admin_roles`.
- Mute is recorded as a moderation state. The chat/API backend must check `muted_until` before accepting messages.
- Ban updates Supabase Auth's ban expiry and revokes current sessions.
- Kick revokes current Supabase sessions. A guest kick blocks that specific heartbeat session UUID for 24 hours.
- IP restrictions are temporary and stored as digests. Shared IPs can represent many people, so use short durations and a documented reason.
- Review the audit log after every action. Protect administrator accounts separately with MFA and least-privilege roles.
