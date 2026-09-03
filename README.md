# soYam Cosmo Backend

Cloudflare Worker API + Supabase PostgreSQL backend for the soYam Cosmo Telegram Mini App.

## Architecture

Telegram Mini App → Cloudflare Worker API → Supabase PostgreSQL

The Worker:
- validates Telegram Mini App `initData`
- resolves CUSTOMER / STAFF / OWNER / DRIVER roles
- issues short-lived HS256 access tokens
- enforces RBAC
- exposes product, inventory, order, payment, staff, delivery and EOD endpoints
- writes audit events
- uses Supabase's server-side secret key only from Worker secrets

Supabase RLS is enabled in the SQL schema. The Worker performs the application-level authorization before using the server secret. Never put `SUPABASE_SECRET_KEY` or `JWT_SECRET` in frontend code or GitHub.

## 1. Create Supabase

Create a project at https://supabase.com/

Open SQL Editor and run `supabase/schema.sql`.

Then copy:
- Project URL
- Secret key (the current server-side secret key; legacy `service_role` also works if your project still uses it)

Supabase recommends secret keys only for server-side components; they bypass RLS and must never be exposed in a browser. See:
https://supabase.com/docs/guides/getting-started/api-keys

## 2. Create Cloudflare Worker

Install Node.js, then:

```bash
npm install
npx wrangler login
npm install
npx wrangler deploy
```

Set secrets:

```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_SECRET_KEY
npx wrangler secret put TELEGRAM_BOT_TOKEN
npx wrangler secret put JWT_SECRET
npx wrangler secret put SOYAM_OWNER_IDS
```

`SOYAM_OWNER_IDS` should contain Telegram numeric user IDs separated by commas, for example:

```text
123456789,987654321
```

Do not use the Telegram username as the primary owner identity. Telegram numeric ID is the stable identifier.

## 3. Local development

Create `.dev.vars` from `.dev.vars.example` and fill it locally.

Then:

```bash
npm run dev
```

The API will normally be available at the local Wrangler URL.

## 4. Connect your existing frontend

Set your frontend API base URL to:

```text
https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev
```

On Telegram Mini App startup, send:

```js
const initData = Telegram.WebApp.initData;

fetch(`${API_BASE}/api/auth/me`, {
  headers: { "X-Telegram-Init-Data": initData }
});
```

The response contains a short-lived access token. Send it on later calls:

```text
Authorization: Bearer <token>
```

For a production frontend, keep the token in memory where practical rather than persistent browser storage.

## API

GET `/health`
GET `/api/auth/me`
GET `/api/products`
POST `/api/orders`
GET `/api/orders`
POST `/api/orders/:id/payment`
GET `/api/payments/pending`
POST `/api/payments/:id/verify`
POST `/api/orders/:id/complete`
GET `/api/inventory`
POST `/api/inventory`
PATCH `/api/inventory/:id`
DELETE `/api/inventory/:id`
GET `/api/staff`
POST `/api/staff`
POST `/api/staff/:id/revoke`
GET `/api/deliveries`
POST `/api/deliveries/:id/dispatch`
POST `/api/deliveries/:id/delivered`
GET `/api/reports/daily`
POST `/api/financial/close`

## Important production notes

1. Payment gateway callbacks should be added as signed server-to-server webhooks when Telebirr/Chapa integration is implemented.
2. Product/payment files should use object storage/CDN signed URLs; do not store raw payment screenshots in database rows.
3. For high-volume deployments, use Supabase/Postgres RPC or database functions for complex atomic operations.
4. The sample order endpoint performs stock checks and decrements inside a Postgres transaction function (`create_order_atomic`).
5. Add automated tests before production launch.
