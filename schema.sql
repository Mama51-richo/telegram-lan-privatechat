-- soYam Cosmo PostgreSQL schema
-- Run this entire file in Supabase SQL Editor.
-- Security model: RLS is enabled; server-side Worker authorization is required.

create extension if not exists pgcrypto;

create type public.staff_status as enum ('ACTIVE','SUSPENDED');
create type public.order_status as enum (
  'PENDING_PAYMENT','PAYMENT_PENDING_REVIEW','PAID',
  'PROCESSING','READY_FOR_PICKUP','OUT_FOR_DELIVERY',
  'DELIVERED','COMPLETED','OWNER_PENDING','CANCELLED'
);
create type public.fulfillment_type as enum ('PICKUP','DELIVERY');
create type public.payment_method as enum ('CASH','BANK_TRANSFER','TELEBIRR');
create type public.payment_status as enum ('PENDING','VERIFIED','REJECTED');

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  telegram_id bigint unique not null,
  username text,
  first_name text,
  last_name text,
  phone text,
  language text default 'en',
  loyalty_points integer not null default 0 check (loyalty_points >= 0),
  loyalty_tier text not null default 'Silver',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.staff (
  id uuid primary key default gen_random_uuid(),
  telegram_id bigint unique not null,
  username text,
  phone text,
  display_name text not null,
  status public.staff_status not null default 'ACTIVE',
  created_by bigint,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.drivers (
  id uuid primary key default gen_random_uuid(),
  telegram_id bigint unique not null,
  display_name text not null,
  phone text,
  status text not null default 'ONLINE' check (status in ('ONLINE','OFFLINE','SUSPENDED')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  name text unique not null,
  slug text unique not null,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  sku text unique not null,
  name text not null,
  category_id uuid references public.categories(id),
  description text,
  image_url text,
  buying_price numeric(12,2) not null default 0 check (buying_price >= 0),
  selling_price numeric(12,2) not null default 0 check (selling_price >= 0),
  stock integer not null default 0 check (stock >= 0),
  low_stock_threshold integer not null default 5 check (low_stock_threshold >= 0),
  barcode text unique,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  order_no text unique not null,
  customer_telegram_id bigint not null,
  status public.order_status not null default 'PENDING_PAYMENT',
  fulfillment public.fulfillment_type not null,
  delivery_address text,
  customer_name text,
  customer_phone text,
  subtotal numeric(12,2) not null default 0,
  delivery_fee numeric(12,2) not null default 0,
  total numeric(12,2) not null default 0,
  idempotency_key text unique,
  seller_telegram_id bigint,
  driver_id uuid references public.drivers(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid not null references public.products(id),
  quantity integer not null check (quantity > 0),
  unit_price numeric(12,2) not null,
  line_total numeric(12,2) not null
);

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  method public.payment_method not null,
  amount numeric(12,2) not null check (amount >= 0),
  proof_url text,
  status public.payment_status not null default 'PENDING',
  verified_by bigint,
  verified_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.deliveries (
  id uuid primary key default gen_random_uuid(),
  order_id uuid unique not null references public.orders(id) on delete cascade,
  driver_id uuid references public.drivers(id),
  status text not null default 'UNASSIGNED'
    check (status in ('UNASSIGNED','ASSIGNED','OUT_FOR_DELIVERY','DELIVERED','FAILED')),
  dispatched_at timestamptz,
  delivered_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.daily_ledger (
  id uuid primary key default gen_random_uuid(),
  ledger_date date unique not null,
  total_units integer not null default 0,
  cash_amount numeric(12,2) not null default 0,
  mobile_amount numeric(12,2) not null default 0,
  expected_revenue numeric(12,2) not null default 0,
  actual_revenue numeric(12,2) not null default 0,
  variance numeric(12,2) not null default 0,
  closed_by bigint,
  closed_at timestamptz,
  locked boolean not null default false
);

create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_telegram_id bigint not null,
  action text not null,
  entity_type text,
  entity_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_users_telegram on public.users(telegram_id);
create index if not exists idx_staff_telegram on public.staff(telegram_id);
create index if not exists idx_staff_status on public.staff(status);
create index if not exists idx_products_active on public.products(active);
create index if not exists idx_orders_customer on public.orders(customer_telegram_id);
create index if not exists idx_orders_status on public.orders(status);
create index if not exists idx_orders_created on public.orders(created_at);
create index if not exists idx_audit_actor on public.audit_logs(actor_telegram_id);

-- Atomic order creation and stock deduction.
create or replace function public.create_order_atomic(
  p_customer_telegram_id bigint,
  p_customer_name text,
  p_customer_phone text,
  p_fulfillment public.fulfillment_type,
  p_delivery_address text,
  p_delivery_fee numeric,
  p_idempotency_key text,
  p_items jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_order_id uuid;
  v_order_no text;
  v_subtotal numeric(12,2) := 0;
  v_item jsonb;
  v_product public.products%rowtype;
  v_qty integer;
  v_line numeric(12,2);
begin
  if p_idempotency_key is not null then
    select id, order_no into v_order_id, v_order_no
    from public.orders
    where idempotency_key = p_idempotency_key;

    if v_order_id is not null then
      return jsonb_build_object('id', v_order_id, 'order_no', v_order_no, 'duplicate', true);
    end if;
  end if;

  if jsonb_array_length(p_items) = 0 then
    raise exception 'ORDER_EMPTY';
  end if;

  v_order_no := 'SY-' || to_char(now(), 'YYYYMMDDHH24MISSMS') || '-' ||
                upper(substr(replace(gen_random_uuid()::text,'-',''),1,6));

  insert into public.orders (
    order_no, customer_telegram_id, customer_name, customer_phone,
    fulfillment, delivery_address, delivery_fee, idempotency_key
  ) values (
    v_order_no, p_customer_telegram_id, p_customer_name, p_customer_phone,
    p_fulfillment, p_delivery_address, coalesce(p_delivery_fee,0), p_idempotency_key
  ) returning id into v_order_id;

  for v_item in select * from jsonb_array_elements(p_items)
  loop
    v_qty := (v_item->>'quantity')::integer;
    if v_qty <= 0 then raise exception 'INVALID_QUANTITY'; end if;

    select * into v_product
    from public.products
    where id = (v_item->>'product_id')::uuid
      and active = true
    for update;

    if not found then raise exception 'PRODUCT_NOT_FOUND'; end if;
    if v_product.stock < v_qty then
      raise exception 'INSUFFICIENT_STOCK:%', v_product.name;
    end if;

    v_line := v_product.selling_price * v_qty;
    v_subtotal := v_subtotal + v_line;

    update public.products
    set stock = stock - v_qty, updated_at = now()
    where id = v_product.id;

    insert into public.order_items(order_id, product_id, quantity, unit_price, line_total)
    values (v_order_id, v_product.id, v_qty, v_product.selling_price, v_line);
  end loop;

  update public.orders
  set subtotal = v_subtotal,
      total = v_subtotal + coalesce(p_delivery_fee,0),
      updated_at = now()
  where id = v_order_id;

  return jsonb_build_object(
    'id', v_order_id,
    'order_no', v_order_no,
    'subtotal', v_subtotal,
    'delivery_fee', coalesce(p_delivery_fee,0),
    'total', v_subtotal + coalesce(p_delivery_fee,0),
    'duplicate', false
  );
exception
  when unique_violation then
    select id, order_no into v_order_id, v_order_no
    from public.orders where idempotency_key = p_idempotency_key;
    if v_order_id is not null then
      return jsonb_build_object('id', v_order_id, 'order_no', v_order_no, 'duplicate', true);
    end if;
    raise;
end;
$$;

-- RLS: deny browser access by default. The Worker uses its server secret.
alter table public.users enable row level security;
alter table public.staff enable row level security;
alter table public.drivers enable row level security;
alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.payments enable row level security;
alter table public.deliveries enable row level security;
alter table public.daily_ledger enable row level security;
alter table public.audit_logs enable row level security;

-- Public catalog read policy for publishable-key clients, if you later use Supabase directly.
drop policy if exists "public_active_products_read" on public.products;
create policy "public_active_products_read"
on public.products for select
to anon, authenticated
using (active = true);

drop policy if exists "public_categories_read" on public.categories;
create policy "public_categories_read"
on public.categories for select
to anon, authenticated
using (true);

-- The atomic function is deliberately not granted to anon/authenticated.
revoke all on function public.create_order_atomic(bigint,text,text,text,text,numeric,text,jsonb)
from public, anon, authenticated;
grant execute on function public.create_order_atomic(bigint,text,text,text,text,numeric,text,jsonb)
to service_role;

-- Seed categories/products for the MVP.
insert into public.categories(name, slug) values
('Skincare','skincare'),
('Makeup','makeup'),
('Fragrance','fragrance'),
('Haircare','haircare'),
('Detergent','detergent')
on conflict (slug) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P001','Luxury Face Cream',id,'Premium face cream',250,420,25,5 from public.categories where slug='skincare'
on conflict (sku) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P002','Hydrating Lotion',id,'Daily hydrating lotion',180,320,30,5 from public.categories where slug='skincare'
on conflict (sku) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P003','Beauty Soap',id,'Beauty cleansing soap',60,110,60,10 from public.categories where slug='detergent'
on conflict (sku) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P004','Fresh Fragrance',id,'Fresh daily fragrance',300,520,20,5 from public.categories where slug='fragrance'
on conflict (sku) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P005','Hair Care Oil',id,'Nourishing hair oil',140,260,35,5 from public.categories where slug='haircare'
on conflict (sku) do nothing;

insert into public.products
(sku,name,category_id,description,buying_price,selling_price,stock,low_stock_threshold)
select 'P006','Premium Makeup',id,'Premium makeup product',350,600,15,5 from public.categories where slug='makeup'
on conflict (sku) do nothing;
