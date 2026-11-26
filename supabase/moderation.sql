-- Nameless Labs moderation control plane.
-- Applied to the connected Supabase project. Keep admin operations behind
-- the custom admin session token; never expose the service-role key in a browser.

-- Existing custom admin auth RPCs use pgcrypto from the extensions schema.
-- Pin that schema in their SECURITY DEFINER search paths so admin re-auth works.
alter function public.admin_login(text,text) set search_path = public, extensions, pg_temp;
alter function public.admin_session(text) set search_path = public, extensions, pg_temp;
alter function public.admin_dashboard(text) set search_path = public, extensions, pg_temp;
alter function public.admin_set_tier(text,uuid,text) set search_path = public, extensions, pg_temp;
alter function public.admin_set_banned(text,uuid,boolean) set search_path = public, extensions, pg_temp;

create table if not exists public.nl_user_moderation (
  user_id uuid primary key references auth.users(id) on delete cascade,
  rank text not null default 'User' check (rank in ('Owner','Admin','Moderator','Premium','User')),
  muted_until timestamptz,
  mute_reason text,
  updated_at timestamptz not null default now(),
  updated_by text
);
create table if not exists public.nl_live_visitors (
  session_id uuid primary key,
  user_id uuid references auth.users(id) on delete set null,
  display_name text not null default 'Guest',
  user_agent text,
  last_seen timestamptz not null default now(),
  ip_digest text
);
create index if not exists nl_live_visitors_seen_idx on public.nl_live_visitors(last_seen desc);
create index if not exists nl_live_visitors_ip_digest_idx on public.nl_live_visitors(ip_digest);
create table if not exists public.nl_blocked_guest_sessions (
  session_id uuid primary key,
  expires_at timestamptz not null,
  reason text not null default 'Kicked by administrator'
);
create table if not exists public.nl_ip_restrictions (
  id bigint generated always as identity primary key,
  ip_digest text not null unique,
  expires_at timestamptz not null,
  reason text not null,
  created_at timestamptz not null default now(),
  created_by text
);
create table if not exists public.nl_moderation_audit (
  id bigint generated always as identity primary key,
  admin_username text not null,
  action text not null,
  target_user_id uuid,
  target_session_id uuid,
  reason text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.nl_user_moderation enable row level security;
alter table public.nl_live_visitors enable row level security;
alter table public.nl_blocked_guest_sessions enable row level security;
alter table public.nl_ip_restrictions enable row level security;
alter table public.nl_moderation_audit enable row level security;

create or replace function public.nl_admin_name(p_token text)
returns text language sql security definer set search_path = ''
as $$
 select a.username from public.admin_sessions s
 join public.admin_accounts a on a.username=s.username
 where s.token_hash=encode(extensions.digest(coalesce(p_token,''),'sha256'),'hex')
   and s.expires_at>now() and a.enabled=true limit 1
$$;
revoke all on function public.nl_admin_name(text) from public, anon, authenticated;

create or replace function public.nl_moderation_overview(p_token text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text; v_result jsonb;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 delete from public.nl_live_visitors where last_seen<now()-interval '3 minutes';
 delete from public.nl_blocked_guest_sessions where expires_at<=now();
 select jsonb_build_object(
  'users',coalesce((select jsonb_agg(jsonb_build_object(
   'id',p.id,'email',p.email,'name',coalesce(p.display_name,p.email,'Unnamed'),
   'tier',p.tier,'banned',p.banned,'created_at',p.created_at,'last_login_at',p.last_login_at,
   'rank',coalesce(m.rank,'User'),'muted_until',m.muted_until,'mute_reason',m.mute_reason,
   'is_admin',exists(select 1 from public.admins ad where ad.user_id=p.id)
  ) order by p.created_at desc) from public.profiles p left join public.nl_user_moderation m on m.user_id=p.id),'[]'::jsonb),
  'visitors',coalesce((select jsonb_agg(jsonb_build_object(
   'session_id',session_id,'user_id',user_id,'name',display_name,'user_agent',user_agent,
   'last_seen',last_seen,'ip_fingerprint',case when ip_digest is null then null else left(ip_digest,12) end
  ) order by last_seen desc) from public.nl_live_visitors where last_seen>=now()-interval '3 minutes'),'[]'::jsonb),
  'ip_restrictions',coalesce((select jsonb_agg(jsonb_build_object(
   'id',id,'expires_at',expires_at,'reason',reason,'created_at',created_at
  ) order by created_at desc) from public.nl_ip_restrictions where expires_at>now()),'[]'::jsonb),
  'audit',coalesce((select jsonb_agg(jsonb_build_object(
   'id',id,'action',action,'target_user_id',target_user_id,'target_session_id',target_session_id,
   'reason',reason,'admin_username',admin_username,'created_at',created_at,'details',details
  ) order by created_at desc) from (select * from public.nl_moderation_audit order by created_at desc limit 150) a),'[]'::jsonb),
  'admin',v_admin,
  'admin_role',(select role from public.admin_accounts where username=v_admin)
 ) into v_result;
 return v_result;
end $$;

create or replace function public.nl_moderate_user(
 p_token text,p_user_id uuid,p_action text,p_value text default null,p_reason text default null
) returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text; v_role text; v_until timestamptz;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 select role into v_role from public.admin_accounts where username=v_admin;
 if exists(select 1 from public.admins where user_id=p_user_id) then raise exception 'Protected administrator account'; end if;
 if not exists(select 1 from public.profiles where id=p_user_id) then raise exception 'User not found'; end if;
 if p_action='rank' then
   if v_role<>'OWNER' then raise exception 'Only the Owner can change ranks'; end if;
   if p_value not in ('Owner','Admin','Moderator','Premium','User') then raise exception 'Invalid rank'; end if;
   insert into public.nl_user_moderation(user_id,rank,updated_by) values(p_user_id,p_value,v_admin)
   on conflict(user_id) do update set rank=excluded.rank,updated_by=v_admin,updated_at=now();
 elsif p_action in ('mute','ban') then
   if p_value='permanent' and p_action='ban' then v_until:=now()+interval '100 years';
   else
     if p_value !~ '^[0-9]+$' or p_value::int not in (5,15,60,1440,10080,43200) then raise exception 'Invalid duration'; end if;
     v_until:=now()+make_interval(mins=>p_value::int);
   end if;
   if p_action='mute' then
     insert into public.nl_user_moderation(user_id,muted_until,mute_reason,updated_by)
     values(p_user_id,v_until,p_reason,v_admin)
     on conflict(user_id) do update set muted_until=excluded.muted_until,mute_reason=excluded.mute_reason,updated_by=v_admin,updated_at=now();
   else
     update public.profiles set banned=true where id=p_user_id;
     update auth.users set banned_until=v_until where id=p_user_id;
     delete from auth.sessions where user_id=p_user_id;
   end if;
 elsif p_action='unmute' then
   update public.nl_user_moderation set muted_until=null,mute_reason=null,updated_by=v_admin,updated_at=now() where user_id=p_user_id;
 elsif p_action='unban' then
   update public.profiles set banned=false where id=p_user_id;
   update auth.users set banned_until=null where id=p_user_id;
 elsif p_action='kick' then
   delete from auth.sessions where user_id=p_user_id;
 else raise exception 'Unsupported moderation action'; end if;
 insert into public.nl_moderation_audit(admin_username,action,target_user_id,reason,details)
 values(v_admin,p_action,p_user_id,p_reason,jsonb_build_object('value',p_value));
 return jsonb_build_object('success',true,'action',p_action);
end $$;

create or replace function public.nl_visitor_heartbeat(p_session_id uuid,p_name text default 'Guest',p_user_agent text default null,p_user_id uuid default null)
returns jsonb language plpgsql security definer set search_path = ''
as $$
begin
 if exists(select 1 from public.nl_blocked_guest_sessions where session_id=p_session_id and expires_at>now()) then
  return jsonb_build_object('allowed',false,'reason','session_kicked');
 end if;
 delete from public.nl_blocked_guest_sessions where expires_at<=now();
 insert into public.nl_live_visitors(session_id,user_id,display_name,user_agent,last_seen)
 values(p_session_id,auth.uid(),left(coalesce(p_name,'Guest'),80),left(coalesce(p_user_agent,''),300),now())
 on conflict(session_id) do update set user_id=auth.uid(),display_name=excluded.display_name,user_agent=excluded.user_agent,last_seen=now();
 return jsonb_build_object('allowed',true);
end $$;

create or replace function public.nl_kick_guest(p_token text,p_session_id uuid,p_reason text default 'Kicked by administrator')
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 delete from public.nl_live_visitors where session_id=p_session_id;
 insert into public.nl_blocked_guest_sessions(session_id,expires_at,reason)
 values(p_session_id,now()+interval '24 hours',left(p_reason,500))
 on conflict(session_id) do update set expires_at=excluded.expires_at,reason=excluded.reason;
 insert into public.nl_moderation_audit(admin_username,action,target_session_id,reason)
 values(v_admin,'guest_kick',p_session_id,p_reason);
 return jsonb_build_object('success',true);
end $$;

create or replace function public.nl_restrict_ip(p_token text,p_ip text,p_minutes integer default 1440,p_reason text default 'Abuse')
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text; v_role text;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 select role into v_role from public.admin_accounts where username=v_admin;
 if v_role<>'OWNER' then raise exception 'Only the Owner can restrict IP addresses'; end if;
 if p_ip is null or length(p_ip)>64 or p_ip !~ '^[0-9a-fA-F:.]+$' then raise exception 'Invalid IPv4/IPv6 address'; end if;
 if p_minutes not in (60,1440,10080,43200,525600) then raise exception 'Invalid duration'; end if;
 insert into public.nl_ip_restrictions(ip_digest,expires_at,reason,created_by)
 values(encode(extensions.digest(lower(trim(p_ip)),'sha256'),'hex'),now()+make_interval(mins=>p_minutes),left(p_reason,500),v_admin)
 on conflict(ip_digest) do update set expires_at=excluded.expires_at,reason=excluded.reason,created_by=v_admin,created_at=now();
 insert into public.nl_moderation_audit(admin_username,action,reason,details)
 values(v_admin,'ip_restrict',p_reason,jsonb_build_object('duration_minutes',p_minutes));
 return jsonb_build_object('success',true);
end $$;

create or replace function public.nl_restrict_visitor_ip(p_token text,p_session_id uuid,p_minutes integer default 1440,p_reason text default 'Abuse')
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text; v_role text; v_digest text;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 select role into v_role from public.admin_accounts where username=v_admin;
 if v_role<>'OWNER' then raise exception 'Only the Owner can restrict IP addresses'; end if;
 if p_minutes not in (60,1440,10080,43200,525600) then raise exception 'Invalid duration'; end if;
 select ip_digest into v_digest from public.nl_live_visitors where session_id=p_session_id;
 if v_digest is null then raise exception 'Visitor IP fingerprint unavailable; refresh and try again'; end if;
 insert into public.nl_ip_restrictions(ip_digest,expires_at,reason,created_by)
 values(v_digest,now()+make_interval(mins=>p_minutes),left(p_reason,500),v_admin)
 on conflict(ip_digest) do update set expires_at=excluded.expires_at,reason=excluded.reason,created_by=excluded.created_by,created_at=now();
 insert into public.nl_moderation_audit(admin_username,action,target_session_id,reason,details)
 values(v_admin,'visitor_ip_restrict',p_session_id,p_reason,jsonb_build_object('duration_minutes',p_minutes,'fingerprint',left(v_digest,12)));
 return jsonb_build_object('success',true);
end $$;

create or replace function public.nl_remove_ip_restriction(p_token text,p_id bigint)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_admin text; v_role text;
begin
 v_admin:=public.nl_admin_name(p_token);
 if v_admin is null then raise exception 'Unauthorized admin session'; end if;
 select role into v_role from public.admin_accounts where username=v_admin;
 if v_role<>'OWNER' then raise exception 'Only the Owner can remove IP restrictions'; end if;
 delete from public.nl_ip_restrictions where id=p_id;
 insert into public.nl_moderation_audit(admin_username,action,details)
 values(v_admin,'ip_unrestrict',jsonb_build_object('restriction_id',p_id));
 return jsonb_build_object('success',true);
end $$;

create or replace function public.nl_ip_is_restricted(p_ip text)
returns boolean language sql security definer set search_path = ''
as $$
 select exists(select 1 from public.nl_ip_restrictions
  where ip_digest=encode(extensions.digest(lower(trim(p_ip)),'sha256'),'hex') and expires_at>now())
$$;

revoke all on function public.nl_moderation_overview(text) from public, authenticated;
revoke all on function public.nl_moderate_user(text,uuid,text,text,text) from public, authenticated;
revoke all on function public.nl_kick_guest(text,uuid,text) from public, authenticated;
revoke all on function public.nl_restrict_ip(text,text,integer,text) from public, authenticated;
revoke all on function public.nl_restrict_visitor_ip(text,uuid,integer,text) from public, authenticated;
revoke all on function public.nl_remove_ip_restriction(text,bigint) from public, authenticated;
grant execute on function public.nl_moderation_overview(text) to anon;
grant execute on function public.nl_moderate_user(text,uuid,text,text,text) to anon;
grant execute on function public.nl_kick_guest(text,uuid,text) to anon;
grant execute on function public.nl_restrict_ip(text,text,integer,text) to anon;
grant execute on function public.nl_restrict_visitor_ip(text,uuid,integer,text) to anon;
grant execute on function public.nl_remove_ip_restriction(text,bigint) to anon;
revoke all on function public.nl_visitor_heartbeat(uuid,text,text,uuid) from public, authenticated;
grant execute on function public.nl_visitor_heartbeat(uuid,text,text,uuid) to anon, authenticated;
revoke all on function public.nl_ip_is_restricted(text) from public, anon, authenticated;
grant execute on function public.nl_ip_is_restricted(text) to service_role;
