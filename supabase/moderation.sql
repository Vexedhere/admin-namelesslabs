-- Nameless Labs moderation control plane
-- Apply after the existing supabase/schema.sql. Never expose the service-role key in the browser.

create extension if not exists pgcrypto;

create table if not exists public.user_moderation (
  user_id uuid primary key references auth.users(id) on delete cascade,
  rank text not null default 'User' check (rank in ('Owner','Admin','Moderator','Premium','User')),
  muted_until timestamptz,
  banned_until timestamptz,
  reason text,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

create table if not exists public.live_visitors (
  session_id uuid primary key,
  user_id uuid references auth.users(id) on delete set null,
  display_name text not null default 'Guest',
  user_agent text,
  last_seen timestamptz not null default now()
);
create index if not exists live_visitors_seen_idx on public.live_visitors(last_seen desc);

create table if not exists public.blocked_guest_sessions (
  session_id uuid primary key,
  expires_at timestamptz not null default now() + interval '24 hours',
  reason text not null default 'Kicked by an administrator',
  created_at timestamptz not null default now()
);

create table if not exists public.ip_restrictions (
  id bigint generated always as identity primary key,
  ip_digest text not null unique,
  expires_at timestamptz,
  reason text not null,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);

create table if not exists public.moderation_audit (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id),
  target_user_id uuid,
  target_session_id uuid,
  action text not null,
  reason text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.user_moderation enable row level security;
alter table public.live_visitors enable row level security;
alter table public.ip_restrictions enable row level security;
alter table public.blocked_guest_sessions enable row level security;
alter table public.moderation_audit enable row level security;
-- Deliberately no direct client policies. All access is through checked RPCs.

create or replace function public.admin_moderation_overview()
returns jsonb language plpgsql security definer set search_path = public, auth as $$
declare result jsonb;
begin
  if not public.is_admin() then raise exception 'Not authorized'; end if;
  delete from public.live_visitors where last_seen < now() - interval '3 minutes';
  select jsonb_build_object(
    'users', coalesce((select jsonb_agg(jsonb_build_object(
      'id',p.id,'email',p.email,'name',p.full_name,'created_at',p.created_at,
      'last_sign_in_at',p.last_sign_in_at,'rank',coalesce(m.rank,'User'),'is_admin',exists(select 1 from public.admin_roles ar where ar.user_id=p.id),
      'muted_until',m.muted_until,'banned_until',m.banned_until,'reason',m.reason
    ) order by p.created_at desc) from public.profiles p
      left join public.user_moderation m on m.user_id=p.id), '[]'::jsonb),
    'visitors', coalesce((select jsonb_agg(jsonb_build_object(
      'session_id',v.session_id,'user_id',v.user_id,'name',v.display_name,
      'user_agent',v.user_agent,'last_seen',v.last_seen
    ) order by v.last_seen desc) from public.live_visitors v
      where v.last_seen >= now() - interval '3 minutes'), '[]'::jsonb),
    'ip_restrictions', coalesce((select jsonb_agg(jsonb_build_object(
      'id',i.id,'expires_at',i.expires_at,'reason',i.reason,'created_at',i.created_at
    ) order by i.created_at desc) from public.ip_restrictions i
      where i.expires_at is null or i.expires_at > now()), '[]'::jsonb),
    'audit', coalesce((select jsonb_agg(jsonb_build_object(
      'id',a.id,'action',a.action,'reason',a.reason,'created_at',a.created_at,
      'actor_id',a.actor_id,'target_user_id',a.target_user_id,'target_session_id',a.target_session_id
    ) order by a.created_at desc) from public.moderation_audit a limit 100), '[]'::jsonb)
  ) into result;
  return result;
end $$;

create or replace function public.admin_moderate_user(
  p_user_id uuid, p_action text, p_value text default null, p_reason text default null
) returns void language plpgsql security definer set search_path = public, auth as $$
declare until_at timestamptz;
begin
  if not public.is_admin() then raise exception 'Not authorized'; end if;
  if p_user_id = auth.uid() then raise exception 'You cannot moderate your own account'; end if;
  if not exists(select 1 from auth.users where id=p_user_id) then raise exception 'User not found'; end if;
  if exists(select 1 from public.admin_roles where user_id=p_user_id) then raise exception 'Admin accounts are protected'; end if;

  if p_action='rank' then
    if p_value not in ('Owner','Admin','Moderator','Premium','User') then raise exception 'Invalid rank'; end if;
    insert into public.user_moderation(user_id,rank,reason,updated_by)
      values(p_user_id,p_value,p_reason,auth.uid())
      on conflict(user_id) do update set rank=excluded.rank,reason=excluded.reason,updated_by=auth.uid(),updated_at=now();
  elsif p_action in ('mute','ban') then
    if p_value='permanent' then until_at := '9999-12-31 23:59:59+00'::timestamptz;
    else
      if p_value !~ '^[0-9]+$' or p_value::int not in (5,15,60,1440,10080,43200) then raise exception 'Invalid duration'; end if;
      until_at := now() + make_interval(mins => p_value::int);
    end if;
    insert into public.user_moderation(user_id,muted_until,banned_until,reason,updated_by)
      values(p_user_id,case when p_action='mute' then until_at end,case when p_action='ban' then until_at end,p_reason,auth.uid())
      on conflict(user_id) do update set
        muted_until=case when p_action='mute' then excluded.muted_until else public.user_moderation.muted_until end,
        banned_until=case when p_action='ban' then excluded.banned_until else public.user_moderation.banned_until end,
        reason=excluded.reason,updated_by=auth.uid(),updated_at=now();
    if p_action='ban' then
      update auth.users set banned_until=coalesce(until_at,'infinity'::timestamptz) where id=p_user_id;
      delete from auth.sessions where user_id=p_user_id;
    end if;
  elsif p_action='unmute' then
    update public.user_moderation set muted_until=null,updated_by=auth.uid(),updated_at=now() where user_id=p_user_id;
  elsif p_action='unban' then
    update public.user_moderation set banned_until=null,updated_by=auth.uid(),updated_at=now() where user_id=p_user_id;
    update auth.users set banned_until=null where id=p_user_id;
  elsif p_action='kick' then
    delete from auth.sessions where user_id=p_user_id;
  else raise exception 'Unsupported action'; end if;

  insert into public.moderation_audit(actor_id,target_user_id,action,reason,details)
  values(auth.uid(),p_user_id,p_action,p_reason,jsonb_build_object('value',p_value));
end $$;

create or replace function public.admin_restrict_ip(
  p_ip text, p_minutes integer default 1440, p_reason text default 'Abuse'
) returns void language plpgsql security definer set search_path = public, auth as $$
declare normalized text;
begin
  if not public.is_admin() then raise exception 'Not authorized'; end if;
  if p_ip is null or length(p_ip)>64 or p_ip !~ '^[0-9a-fA-F:.]+$' then raise exception 'Enter a valid IPv4 or IPv6 address'; end if;
  if p_minutes not in (60,1440,10080,43200,525600) then raise exception 'Invalid restriction duration'; end if;
  normalized := lower(trim(p_ip));
  insert into public.ip_restrictions(ip_digest,expires_at,reason,created_by)
  values(encode(digest(normalized,'sha256'),'hex'),now()+make_interval(mins=>p_minutes),left(coalesce(p_reason,'Abuse'),500),auth.uid())
  on conflict(ip_digest) do update set expires_at=excluded.expires_at,reason=excluded.reason,created_by=auth.uid(),created_at=now();
  insert into public.moderation_audit(actor_id,action,reason,details)
  values(auth.uid(),'ip_restrict',p_reason,jsonb_build_object('duration_minutes',p_minutes));
end $$;

create or replace function public.admin_remove_ip_restriction(p_id bigint)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Not authorized'; end if;
  delete from public.ip_restrictions where id=p_id;
  insert into public.moderation_audit(actor_id,action,details)
  values(auth.uid(),'ip_unrestrict',jsonb_build_object('restriction_id',p_id));
end $$;

create or replace function public.is_ip_restricted(p_ip text)
returns boolean language sql security definer set search_path = public as $$
  select exists(select 1 from public.ip_restrictions
    where ip_digest=encode(digest(lower(trim(p_ip)),'sha256'),'hex')
      and (expires_at is null or expires_at>now()))
$$;

create or replace function public.visitor_heartbeat(p_session_id uuid, p_name text default 'Guest', p_user_agent text default null)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if exists(select 1 from public.blocked_guest_sessions where session_id=p_session_id and expires_at>now()) then
    raise exception 'This visitor session has been kicked';
  end if;
  delete from public.blocked_guest_sessions where expires_at<=now();
  insert into public.live_visitors(session_id,user_id,display_name,user_agent,last_seen)
  values(p_session_id,auth.uid(),left(coalesce(p_name,'Guest'),80),left(coalesce(p_user_agent,''),300),now())
  on conflict(session_id) do update set user_id=auth.uid(),display_name=excluded.display_name,
    user_agent=excluded.user_agent,last_seen=now();
end $$;

create or replace function public.admin_kick_visitor(p_session_id uuid)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.is_admin() then raise exception 'Not authorized'; end if;
  delete from public.live_visitors where session_id=p_session_id;
  insert into public.blocked_guest_sessions(session_id,expires_at) values(p_session_id,now()+interval '24 hours')
    on conflict(session_id) do update set expires_at=excluded.expires_at;
  insert into public.moderation_audit(actor_id,target_session_id,action)
  values(auth.uid(),p_session_id,'guest_kick');
end $$;

revoke all on function public.is_ip_restricted(text) from public, anon, authenticated;
grant execute on function public.is_ip_restricted(text) to service_role;

revoke all on function public.admin_moderation_overview() from public, anon;
revoke all on function public.admin_moderate_user(uuid,text,text,text) from public, anon;
revoke all on function public.admin_restrict_ip(text,integer,text) from public, anon;
revoke all on function public.admin_remove_ip_restriction(bigint) from public, anon;
revoke all on function public.admin_kick_visitor(uuid) from public, anon;
grant execute on function public.admin_moderation_overview() to authenticated;
grant execute on function public.admin_moderate_user(uuid,text,text,text) to authenticated;
grant execute on function public.admin_restrict_ip(text,integer,text) to authenticated;
grant execute on function public.admin_remove_ip_restriction(bigint) to authenticated;
grant execute on function public.admin_kick_visitor(uuid) to authenticated;
grant execute on function public.visitor_heartbeat(uuid,text,text) to anon, authenticated;
