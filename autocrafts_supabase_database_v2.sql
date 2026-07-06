-- Autocrafts Cashflow System - Supabase Database
-- Run this once in Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  full_name text,
  role text not null default 'staff' check (role in ('owner','admin','staff')),
  approved boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.cashflow_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  record_date date not null,
  transaction_type text not null check (transaction_type in ('income','expense')),
  category text not null,
  description text,
  qty numeric not null default 1,
  amount numeric not null default 0,
  payment_method text,
  total numeric not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.cashflow_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  report_date date not null default current_date,
  report_title text not null,
  total_income numeric not null default 0,
  total_expenses numeric not null default 0,
  net_revenue numeric not null default 0,
  report_html text,
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, approved, role)
  values (new.id, coalesce(new.email,''), coalesce(new.raw_user_meta_data->>'full_name',''), false, 'staff')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists cashflow_transactions_updated_at on public.cashflow_transactions;
create trigger cashflow_transactions_updated_at
before update on public.cashflow_transactions
for each row execute procedure public.set_updated_at();

alter table public.profiles enable row level security;
alter table public.cashflow_transactions enable row level security;
alter table public.cashflow_reports enable row level security;

-- Helper condition: logged-in user must be approved.
-- Users can see their own profile.
drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own" on public.profiles
for select to authenticated
using (auth.uid() = id);

-- Owners/admins can see all profiles.
drop policy if exists "profiles_select_admin" on public.profiles;
create policy "profiles_select_admin" on public.profiles
for select to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true and p.role in ('owner','admin')));

-- Owners/admins can approve/edit profiles.
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles
for update to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true and p.role in ('owner','admin')))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true and p.role in ('owner','admin')));

-- Approved users can read all transactions.
drop policy if exists "transactions_select_approved" on public.cashflow_transactions;
create policy "transactions_select_approved" on public.cashflow_transactions
for select to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

-- Approved users can insert transactions as themselves.
drop policy if exists "transactions_insert_approved" on public.cashflow_transactions;
create policy "transactions_insert_approved" on public.cashflow_transactions
for insert to authenticated
with check (user_id = auth.uid() and exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

-- Approved users can update/delete. Change this to user_id = auth.uid() only if staff should edit only their own entries.
drop policy if exists "transactions_update_approved" on public.cashflow_transactions;
create policy "transactions_update_approved" on public.cashflow_transactions
for update to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

drop policy if exists "transactions_delete_approved" on public.cashflow_transactions;
create policy "transactions_delete_approved" on public.cashflow_transactions
for delete to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

-- Reports.
drop policy if exists "reports_select_approved" on public.cashflow_reports;
create policy "reports_select_approved" on public.cashflow_reports
for select to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

drop policy if exists "reports_insert_approved" on public.cashflow_reports;
create policy "reports_insert_approved" on public.cashflow_reports
for insert to authenticated
with check (user_id = auth.uid() and exists (select 1 from public.profiles p where p.id = auth.uid() and p.approved = true));

-- Realtime support.
alter publication supabase_realtime add table public.cashflow_transactions;
alter publication supabase_realtime add table public.cashflow_reports;

-- After signing up, approve yourself by running this and replacing the email:
-- update public.profiles set approved = true, role = 'owner' where email = 'YOUR_EMAIL@gmail.com';
