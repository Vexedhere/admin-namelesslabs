-- Nameless Labs admin console · Supabase schema
-- Run in Supabase → SQL Editor. Safe to re-run.

-- ───────── tables ─────────
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  created_at timestamptz not null default now(),
  last_sign_in_at timestamptz
);

create table if not exists public.plans (
  id bigint generated always as identity primary key,
  name text not null unique,
  price_inr numeric(12,2) not null,           -- monthly price
  created_at timestamptz not null default now()
);

create table if not exists public.subscriptions (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  plan_id bigint not null references public.plans(id),
  status text not null default 'active' check (status in ('active','trialing','past_due','cancelled')),
  amount_inr numeric(12,2) not null,
  started_at timestamptz not null default now(),
  renews_at timestamptz
);
create index if not exists subs_user_idx on public.subscriptions(user_id);

create table if not exists public.login_events (
  id bigint generated always as identity primary key,
  user_id uuid,
  email text,
  full_name text,
  success boolean not null default true,
  ip text,
  user_agent text,
  created_at timestamptz not null default now()
);
create index if not exists login_events_time_idx on public.login_events(created_at desc);

create table if not exists public.admin_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  full_name text,
  role text not null check (role in ('CEO','Founder','IT Admin','CMO'))
);

-- ───────── helper: is the caller an admin? ─────────
create or replace function public.is_admin() returns boolean
language sql security definer set search_path = public stable as
$$ select exists (select 1 from public.admin_roles where user_id = auth.uid()) $$;

-- ───────── row-level security: only admins can read; customers see only themselves ─────────
alter table public.profiles       enable row level security;
alter table public.plans          enable row level security;
alter table public.subscriptions  enable row level security;
alter table public.login_events   enable row level security;
alter table public.admin_roles    enable row level security;

drop policy if exists "admin read profiles" on public.profiles;
create policy "admin read profiles" on public.profiles for select using (public.is_admin() or id = auth.uid());
drop policy if exists "admin read plans" on public.plans;
create policy "admin read plans" on public.plans for select using (true);
drop policy if exists "admin read subs" on public.subscriptions;
create policy "admin read subs" on public.subscriptions for select using (public.is_admin() or user_id = auth.uid());
drop policy if exists "admin read logins" on public.login_events;
create policy "admin read logins" on public.login_events for select using (public.is_admin());
drop policy if exists "admin read roles" on public.admin_roles;
create policy "admin read roles" on public.admin_roles for select using (public.is_admin() or user_id = auth.uid());
-- No insert/update/delete policies: writes happen via triggers (below) or your server using the service_role key.

-- ───────── automatically create a profile on sign-up ─────────
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email,'@',1)))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ───────── record every successful sign-in (who logged in, when) ─────────
create or replace function public.log_signin() returns trigger
language plpgsql security definer set search_path = public as $$
declare p public.profiles;
begin
  if new.last_sign_in_at is distinct from old.last_sign_in_at then
    update public.profiles set last_sign_in_at = new.last_sign_in_at where id = new.id returning * into p;
    insert into public.login_events (user_id, email, full_name, success, created_at)
    values (new.id, new.email, p.full_name, true, new.last_sign_in_at);
  end if;
  return new;
end $$;
drop trigger if exists on_auth_user_signin on auth.users;
create trigger on_auth_user_signin after update of last_sign_in_at on auth.users
  for each row execute function public.log_signin();

-- ───────── starter plans (edit to match what you sell) ─────────
insert into public.plans (name, price_inr) values
  ('Starter', 499), ('Pro', 1499), ('Business', 4999), ('Enterprise', 14999)
on conflict (name) do nothing;

-- ═════════ ADMIN ROLES ═════════
-- Run this AFTER creating the 4 users in Authentication → Users
-- (chethan@namelesslabs.in.net, vijay@…, itadmin@…, kedar@…).
insert into public.admin_roles (user_id, username, full_name, role)
select u.id, v.username, v.full_name, v.role
from (values
  ('chethan','Chethan','CEO'),
  ('vijay',  'Vijay',  'Founder'),
  ('itadmin','IT Admin','IT Admin'),
  ('kedar',  'Kedar',  'CMO')
) as v(username, full_name, role)
join auth.users u on u.email = v.username || '@namelesslabs.in.net'
on conflict (user_id) do update set role = excluded.role, full_name = excluded.full_name;
