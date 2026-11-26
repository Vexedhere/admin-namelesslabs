// Supabase Edge Function: IP enforcement middleware.
// Deploy with: supabase functions deploy ip-guard
// Configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY as function secrets.
// Call this from a trusted server/proxy path before forwarding traffic to NamelessAI.
// Never expose the service-role key to the browser.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

Deno.serve(async (req) => {
  const forwarded = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const ip = req.headers.get("cf-connecting-ip")?.trim() || forwarded;
  if (!ip) return new Response("Unable to verify network address", { status: 400 });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } },
  );
  const { data, error } = await supabase.rpc("is_ip_restricted", { p_ip: ip });
  if (error) return new Response("Moderation check unavailable", { status: 503 });
  if (data === true) return new Response("Access restricted by Nameless Labs moderation.", {
    status: 403, headers: { "content-type": "text/plain; charset=utf-8" },
  });
  return new Response("OK", { status: 200 });
});
