# Nameless Labs moderation rollout

## Live Supabase deployment

The moderation schema has been applied to the connected Supabase project `nzaelikbjumaidaombmp`. The `ip-guard` Edge Function is deployed (version 2).

The schema creates:
- Account rank and mute state in `nl_user_moderation`
- Live browser sessions in `nl_live_visitors`
- 24-hour guest-session kick blocks
- Temporary IP restrictions stored as SHA-256 fingerprints
- A moderation audit trail

All moderation RPCs validate the existing custom admin session token against `admin_sessions` and `admin_accounts`. Only the OWNER admin can change ranks or create/remove IP restrictions. Existing Supabase admin accounts are protected from moderation. Raw IP addresses are not stored.

## Open the console

Sign in through the existing Nameless Labs dashboard, then open **Moderation center**, or visit `/admin-namelesslabs/moderation.html`.

The page uses the existing `nl_session` session object and calls these live RPCs:
- `nl_moderation_overview`
- `nl_moderate_user`
- `nl_kick_guest`
- `nl_restrict_ip`
- `nl_restrict_visitor_ip`
- `nl_remove_ip_restriction`

## Visitor tracking frontend integration

The NamelessAI frontend integration has been committed to `Vexedhere/namelessai` (heartbeat + Edge IP guard on a 30-second interval, plus server-side kick/ban/mute checks on `/api/chat`). Those changes become active after the main app's deployment succeeds. The underlying heartbeat call is:

```ts
const { data, error } = await supabase.rpc('nl_visitor_heartbeat', {
  p_session_id: browserSessionUuid,
  p_name: displayName || 'Guest',
  p_user_agent: navigator.userAgent,
});
if (error || data?.allowed === false) {
  // Stop the current session and show the moderation message.
}
```

Generate `browserSessionUuid` once per browser tab/session using `crypto.randomUUID()` and keep it in `sessionStorage`. The database derives the authenticated user from the Supabase JWT; it does not trust a caller-supplied user ID.

## IP capture and enforcement

The deployed Edge Function endpoint is:

`https://nzaelikbjumaidaombmp.supabase.co/functions/v1/ip-guard`

Call it directly from the browser (not through a server proxy) so Supabase Edge can observe the connecting client address. The request body should include the same browser session UUID:

```ts
const response = await fetch(
  'https://nzaelikbjumaidaombmp.supabase.co/functions/v1/ip-guard',
  {
    method: 'POST',
    headers: {
      apikey: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ session_id: browserSessionUuid }),
  },
);
if (response.status === 403) {
  // Stop the session: the visitor's IP address is restricted.
}
```

The Edge Function uses the trusted Cloudflare connecting-IP header, checks the IP restriction table, and associates only a short SHA-256 fingerprint with the live session. It does not accept arbitrary `X-Forwarded-For` values and does not store raw IPs. The admin page can block an active visitor's fingerprint directly. A network may be shared by multiple people.

**Important:** The frontend source now calls both endpoints, but the Live visitors tab will not populate until the updated NamelessAI deployment is live and visitors load it. The app checks the Edge Function response and blocks the UI on HTTP 403.

## Moderation behavior

- **Rank:** application rank stored separately from Supabase console permissions.
- **Mute:** stored with expiry and enforced on inserts into `public.chat_messages`. Any other chat/AI API endpoint must also check the moderation state before processing requests.
- **Ban:** marks `profiles.banned`, sets Supabase Auth `banned_until` (100-year expiry for permanent bans), and revokes refreshable sessions.
- **Kick:** revokes current Supabase Auth sessions. For guests, the browser session UUID is blocked for 24 hours.
- **IP restriction:** temporary; SHA-256 fingerprint only. A visitor fingerprint can be blocked from the Live visitors tab. Shared networks can affect multiple people.

## Security notes

Never expose the Supabase service-role key in frontend code. Keep the `ip-guard` function's service-role credential in Supabase's managed Edge Function environment. The moderation tables have RLS enabled and no direct client table policies; access is through the checked RPC functions.