const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  // For Telegram Mini Apps, replace this with your exact production frontend origin
  // once deployed. "*" is convenient for the initial MVP but should be narrowed.
  const allowed = origin || "*";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Telegram-Init-Data, Idempotency-Key",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function response(data, status, request) {
  return json(data, status, corsHeaders(request));
}

function b64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function utf8(s) {
  return new TextEncoder().encode(s);
}

function fromB64url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function hmacSha256(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(message)));
}

async function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
  return result === 0;
}

function parseTelegramInitData(initData) {
  const params = new URLSearchParams(initData || "");
  const data = {};
  for (const [k, v] of params.entries()) data[k] = v;
  return { params, data };
}

async function verifyTelegramInitData(initData, botToken) {
  if (!initData || !botToken) throw new Error("TELEGRAM_AUTH_MISSING");

  const { params, data } = parseTelegramInitData(initData);
  const receivedHash = params.get("hash");
  if (!receivedHash) throw new Error("TELEGRAM_HASH_MISSING");

  const authDate = Number(params.get("auth_date"));
  if (!Number.isFinite(authDate)) throw new Error("TELEGRAM_AUTH_DATE_MISSING");

  // Reject stale Mini App init data. 24 hours is intentionally conservative.
  if (Math.floor(Date.now() / 1000) - authDate > 86400) {
    throw new Error("TELEGRAM_INIT_DATA_EXPIRED");
  }

  params.delete("hash");
  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = await crypto.subtle.digest("SHA-256", utf8(botToken));
  const key = await crypto.subtle.importKey(
    "raw", secretKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const calculated = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, utf8(dataCheckString))
  );

  const expectedHex = [...calculated].map(b => b.toString(16).padStart(2, "0")).join("");
  if (expectedHex.length !== receivedHash.length) throw new Error("TELEGRAM_AUTH_INVALID");

  let mismatch = 0;
  for (let i = 0; i < expectedHex.length; i++) {
    mismatch |= expectedHex.charCodeAt(i) ^ receivedHash.charCodeAt(i);
  }
  if (mismatch !== 0) throw new Error("TELEGRAM_AUTH_INVALID");

  let user = null;
  if (data.user) {
    try { user = JSON.parse(data.user); } catch { throw new Error("TELEGRAM_USER_INVALID"); }
  }
  if (!user?.id) throw new Error("TELEGRAM_USER_MISSING");

  return user;
}

async function signJwt(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = x => b64url(utf8(JSON.stringify(x)));
  const body = enc(header) + "." + enc(payload);
  const sig = await hmacSha256(secret, body);
  return body + "." + b64url(sig);
}

async function verifyJwt(token, secret) {
  const parts = (token || "").split(".");
  if (parts.length !== 3) throw new Error("TOKEN_INVALID");
  const [h, p, s] = parts;
  const expected = await hmacSha256(secret, `${h}.${p}`);
  const actual = fromB64url(s);
  if (!(await timingSafeEqual(expected, actual))) throw new Error("TOKEN_INVALID");

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(fromB64url(p)));
  } catch {
    throw new Error("TOKEN_INVALID");
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) throw new Error("TOKEN_EXPIRED");
  if (payload.iss && payload.iss !== "soyam-cosmo") throw new Error("TOKEN_INVALID");
  return payload;
}

async function authFromRequest(request, env, requiredRoles = []) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) {
    try {
      const payload = await verifyJwt(auth.slice(7), env.JWT_SECRET);
      const roles = payload.roles || [];
      if (requiredRoles.length && !requiredRoles.some(r => roles.includes(r))) {
        throw new Error("FORBIDDEN");
      }
      return payload;
    } catch (e) {
      if (e.message === "FORBIDDEN") throw e;
      throw new Error("UNAUTHORIZED");
    }
  }

  // Allow initial /api/auth/me to authenticate directly with Telegram initData.
  const initData = request.headers.get("X-Telegram-Init-Data");
  if (initData) {
    const tgUser = await verifyTelegramInitData(initData, env.TELEGRAM_BOT_TOKEN);
    const session = await resolveUser(tgUser, env);
    if (requiredRoles.length && !requiredRoles.some(r => session.roles.includes(r))) {
      throw new Error("FORBIDDEN");
    }
    return session;
  }

  throw new Error("UNAUTHORIZED");
}

function ownerIds(env) {
  return new Set(
    String(env.SOYAM_OWNER_IDS || "")
      .split(",").map(s => s.trim()).filter(Boolean).map(Number)
  );
}

async function supabaseFetch(env, path, options = {}) {
  const headers = {
    apikey: env.SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${env.SUPABASE_SECRET_KEY}`,
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  const url = `${env.SUPABASE_URL.replace(/\/$/, "")}/rest/v1/${path}`;
  const res = await fetch(url, { ...options, headers });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const err = new Error(body?.message || body?.hint || `SUPABASE_${res.status}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

async function supabaseRpc(env, name, args) {
  return supabaseFetch(env, `rpc/${name}`, {
    method: "POST",
    body: JSON.stringify(args),
  });
}

async function resolveUser(tgUser, env) {
  const id = Number(tgUser.id);
  const roles = [];
  if (ownerIds(env).has(id)) roles.push("OWNER");

  const staffRows = await supabaseFetch(
    env,
    `staff?telegram_id=eq.${id}&status=eq.ACTIVE&select=id,telegram_id,username,phone,display_name,status`
  );
  if (staffRows?.length) roles.push("STAFF");

  const driverRows = await supabaseFetch(
    env,
    `drivers?telegram_id=eq.${id}&status=neq.SUSPENDED&select=id,telegram_id,display_name,phone,status`
  );
  if (driverRows?.length) roles.push("DRIVER");

  if (!roles.length) roles.push("CUSTOMER");

  // Implicit customer registration.
  await supabaseFetch(env, "users", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({
      telegram_id: id,
      username: tgUser.username || null,
      first_name: tgUser.first_name || null,
      last_name: tgUser.last_name || null,
      updated_at: new Date().toISOString(),
    }),
  });

  return {
    sub: String(id),
    telegram_id: id,
    username: tgUser.username || null,
    first_name: tgUser.first_name || null,
    last_name: tgUser.last_name || null,
    roles,
    staff: staffRows?.[0] || null,
    driver: driverRows?.[0] || null,
  };
}

async function issueSession(user, env) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt({
    iss: env.JWT_ISSUER || "soyam-cosmo",
    sub: user.sub,
    telegram_id: user.telegram_id,
    roles: user.roles,
    iat: now,
    exp: now + Number(env.JWT_TTL_SECONDS || 3600),
    jti: crypto.randomUUID(),
  }, env.JWT_SECRET);
}

async function audit(env, actor, action, entityType = null, entityId = null, metadata = {}) {
  try {
    await supabaseFetch(env, "audit_logs", {
      method: "POST",
      body: JSON.stringify({
        actor_telegram_id: Number(actor.telegram_id),
        action,
        entity_type: entityType,
        entity_id: entityId ? String(entityId) : null,
        metadata,
      }),
    });
  } catch (_) {
    // Do not hide the primary business result because audit logging failed.
    // Production monitoring should alert on this condition.
  }
}

function route(path) {
  return path.replace(/\/+$/, "") || "/";
}

async function bodyJson(request) {
  try { return await request.json(); }
  catch { throw new Error("INVALID_JSON"); }
}

function idFromPath(path, prefix) {
  const re = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/([^/]+)$`);
  return path.match(re)?.[1] || null;
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = route(url.pathname);
  const method = request.method;

  if (method === "OPTIONS") return response(null, 204, request);
  if (method === "GET" && path === "/health") {
    return response({ ok: true, service: "soYam Cosmo API", time: new Date().toISOString() }, 200, request);
  }

  try {
    // Authentication
    if (method === "GET" && path === "/api/auth/me") {
      const user = await authFromRequest(request, env);
      const token = request.headers.get("Authorization") ? null : await issueSession(user, env);
      return response({ ok: true, user, token }, 200, request);
    }

    // Public catalog
    if (method === "GET" && path === "/api/products") {
      const category = url.searchParams.get("category");
      const q = url.searchParams.get("q");
      let query = "products?active=eq.true&select=*,categories(id,name,slug)&order=name.asc";
      const filters = [];
      if (category) filters.push(`categories.slug=eq.${encodeURIComponent(category)}`);
      if (q) filters.push(`name=ilike.*${encodeURIComponent(q)}*`);
      if (filters.length) query += "&" + filters.join("&");
      const products = await supabaseFetch(env, query);
      return response({ ok: true, products }, 200, request);
    }

    // Customer orders
    if (method === "POST" && path === "/api/orders") {
      const actor = await authFromRequest(request, env, ["CUSTOMER","STAFF","OWNER"]);
      const body = await bodyJson(request);
      if (!Array.isArray(body.items)) throw new Error("ITEMS_REQUIRED");

      const result = await supabaseRpc(env, "create_order_atomic", {
        p_customer_telegram_id: Number(actor.telegram_id),
        p_customer_name: body.customer_name || null,
        p_customer_phone: body.customer_phone || null,
        p_fulfillment: body.fulfillment === "DELIVERY" ? "DELIVERY" : "PICKUP",
        p_delivery_address: body.delivery_address || null,
        p_delivery_fee: Number(body.delivery_fee || 0),
        p_idempotency_key: request.headers.get("Idempotency-Key") || body.idempotency_key || null,
        p_items: body.items,
      });
      await audit(env, actor, "ORDER_CREATED", "order", result?.id, { order_no: result?.order_no });
      return response({ ok: true, order: result }, 201, request);
    }

    if (method === "GET" && path === "/api/orders") {
      const actor = await authFromRequest(request, env, ["CUSTOMER","STAFF","OWNER"]);
      let query = "orders?select=*,order_items(*,products(sku,name,image_url)),payments(*),deliveries(*)&order=created_at.desc";
      if (actor.roles.includes("CUSTOMER") && !actor.roles.some(r => ["STAFF","OWNER"].includes(r))) {
        query += `&customer_telegram_id=eq.${Number(actor.telegram_id)}`;
      }
      const orders = await supabaseFetch(env, query);
      return response({ ok: true, orders }, 200, request);
    }

    // Payment proof
    const paymentOrderId = idFromPath(path, "/api/orders");
    if (method === "POST" && paymentOrderId && path.endsWith("/payment")) {
      const actor = await authFromRequest(request, env, ["CUSTOMER"]);
      const body = await bodyJson(request);
      const rows = await supabaseFetch(
        env,
        `orders?id=eq.${encodeURIComponent(paymentOrderId)}&customer_telegram_id=eq.${Number(actor.telegram_id)}&select=id,total,status`
      );
      if (!rows.length) throw new Error("ORDER_NOT_FOUND");
      const order = rows[0];
      await supabaseFetch(env, "payments", {
        method: "POST",
        body: JSON.stringify({
          order_id: order.id,
          method: body.method,
          amount: Number(body.amount ?? order.total),
          proof_url: body.proof_url || null,
          status: "PENDING",
        }),
      });
      await supabaseFetch(env, `orders?id=eq.${order.id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ status: "PAYMENT_PENDING_REVIEW", updated_at: new Date().toISOString() }),
      });
      await audit(env, actor, "PAYMENT_PROOF_SUBMITTED", "order", order.id);
      return response({ ok: true }, 201, request);
    }

    if (method === "GET" && path === "/api/payments/pending") {
      await authFromRequest(request, env, ["STAFF","OWNER"]);
      const payments = await supabaseFetch(
        env,
        "payments?status=eq.PENDING&select=*,orders(order_no,customer_name,customer_phone,total,fulfillment,delivery_address)&order=created_at.asc"
      );
      return response({ ok: true, payments }, 200, request);
    }

    const paymentId = path.match(/^\/api\/payments\/([^/]+)\/verify$/)?.[1];
    if (method === "POST" && paymentId) {
      const actor = await authFromRequest(request, env, ["STAFF","OWNER"]);
      const body = await bodyJson(request);
      const status = body.status === "REJECTED" ? "REJECTED" : "VERIFIED";
      const paymentRows = await supabaseFetch(
        env,
        `payments?id=eq.${encodeURIComponent(paymentId)}&select=id,order_id,amount,status`
      );
      if (!paymentRows.length) throw new Error("PAYMENT_NOT_FOUND");
      const payment = paymentRows[0];

      await supabaseFetch(env, `payments?id=eq.${payment.id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          status,
          verified_by: Number(actor.telegram_id),
          verified_at: new Date().toISOString(),
        }),
      });

      await supabaseFetch(env, `orders?id=eq.${payment.order_id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          status: status === "VERIFIED" ? "PAID" : "PENDING_PAYMENT",
          seller_telegram_id: Number(actor.telegram_id),
          updated_at: new Date().toISOString(),
        }),
      });

      await audit(env, actor, "PAYMENT_VERIFIED", "payment", payment.id, { status });
      return response({ ok: true, status }, 200, request);
    }

    // Inventory
    if (method === "GET" && path === "/api/inventory") {
      await authFromRequest(request, env, ["STAFF","OWNER"]);
      const products = await supabaseFetch(
        env,
        "products?select=*,categories(id,name,slug)&order=stock.asc,name.asc"
      );
      return response({ ok: true, products }, 200, request);
    }

    if (method === "POST" && path === "/api/inventory") {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      const body = await bodyJson(request);
      if (!body.sku || !body.name) throw new Error("SKU_AND_NAME_REQUIRED");
      const rows = await supabaseFetch(env, "products", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          sku: body.sku,
          name: body.name,
          category_id: body.category_id || null,
          description: body.description || null,
          image_url: body.image_url || null,
          buying_price: Number(body.buying_price || 0),
          selling_price: Number(body.selling_price || 0),
          stock: Number(body.stock || 0),
          low_stock_threshold: Number(body.low_stock_threshold ?? 5),
          barcode: body.barcode || null,
          active: true,
        }),
      });
      await audit(env, actor, "PRODUCT_CREATED", "product", rows?.[0]?.id);
      return response({ ok: true, product: rows?.[0] }, 201, request);
    }

    const inventoryId = path.match(/^\/api\/inventory\/([^/]+)$/)?.[1];
    if (inventoryId && method === "PATCH") {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      const body = await bodyJson(request);
      const allowed = ["name","category_id","description","image_url","buying_price","selling_price","stock","low_stock_threshold","barcode","active"];
      const patch = {};
      for (const key of allowed) if (key in body) patch[key] = body[key];
      patch.updated_at = new Date().toISOString();
      const rows = await supabaseFetch(env, `products?id=eq.${encodeURIComponent(inventoryId)}`, {
        method: "PATCH",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify(patch),
      });
      if (!rows.length) throw new Error("PRODUCT_NOT_FOUND");
      await audit(env, actor, "PRODUCT_UPDATED", "product", inventoryId, patch);
      return response({ ok: true, product: rows[0] }, 200, request);
    }

    if (inventoryId && method === "DELETE") {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      await supabaseFetch(env, `products?id=eq.${encodeURIComponent(inventoryId)}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ active: false, updated_at: new Date().toISOString() }),
      });
      await audit(env, actor, "PRODUCT_ARCHIVED", "product", inventoryId);
      return response({ ok: true }, 200, request);
    }

    // Staff registry
    if (method === "GET" && path === "/api/staff") {
      await authFromRequest(request, env, ["OWNER"]);
      const staff = await supabaseFetch(env, "staff?select=*&order=created_at.desc");
      return response({ ok: true, staff }, 200, request);
    }

    if (method === "POST" && path === "/api/staff") {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      const body = await bodyJson(request);
      if (!body.telegram_id || !body.display_name) throw new Error("TELEGRAM_ID_AND_NAME_REQUIRED");
      const rows = await supabaseFetch(env, "staff", {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          telegram_id: Number(body.telegram_id),
          username: body.username || null,
          phone: body.phone || null,
          display_name: body.display_name,
          status: "ACTIVE",
          created_by: Number(actor.telegram_id),
        }),
      });
      await audit(env, actor, "STAFF_CREATED", "staff", rows?.[0]?.id);
      return response({ ok: true, staff: rows?.[0] }, 201, request);
    }

    const staffId = path.match(/^\/api\/staff\/([^/]+)\/revoke$/)?.[1];
    if (method === "POST" && staffId) {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      const rows = await supabaseFetch(env, `staff?id=eq.${encodeURIComponent(staffId)}&select=id,telegram_id`);
      if (!rows.length) throw new Error("STAFF_NOT_FOUND");
      await supabaseFetch(env, `staff?id=eq.${rows[0].id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ status: "SUSPENDED", updated_at: new Date().toISOString() }),
      });
      await audit(env, actor, "STAFF_REVOKED", "staff", staffId, { telegram_id: rows[0].telegram_id });
      return response({
        ok: true,
        status: "SUSPENDED",
        note: "Existing JWTs expire naturally; a production denylist can be added with a session table."
      }, 200, request);
    }

    // Delivery
    if (method === "GET" && path === "/api/deliveries") {
      await authFromRequest(request, env, ["DRIVER","STAFF","OWNER"]);
      const deliveries = await supabaseFetch(
        env,
        "deliveries?select=*,orders(order_no,customer_name,customer_phone,delivery_address,total,status),drivers(id,display_name,phone,status)&order=created_at.desc"
      );
      return response({ ok: true, deliveries }, 200, request);
    }

    const dispatchId = path.match(/^\/api\/deliveries\/([^/]+)\/dispatch$/)?.[1];
    if (method === "POST" && dispatchId) {
      const actor = await authFromRequest(request, env, ["STAFF","OWNER"]);
      const body = await bodyJson(request);
      if (!body.driver_id) throw new Error("DRIVER_ID_REQUIRED");
      const rows = await supabaseFetch(env, `deliveries?id=eq.${encodeURIComponent(dispatchId)}&select=id,order_id`);
      if (!rows.length) throw new Error("DELIVERY_NOT_FOUND");
      await supabaseFetch(env, `deliveries?id=eq.${rows[0].id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          driver_id: body.driver_id,
          status: "ASSIGNED",
          updated_at: new Date().toISOString(),
        }),
      });
      await supabaseFetch(env, `orders?id=eq.${rows[0].order_id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ status: "OUT_FOR_DELIVERY", updated_at: new Date().toISOString() }),
      });
      await audit(env, actor, "DELIVERY_DISPATCHED", "delivery", dispatchId, { driver_id: body.driver_id });
      return response({ ok: true }, 200, request);
    }

    const deliveredId = path.match(/^\/api\/deliveries\/([^/]+)\/delivered$/)?.[1];
    if (method === "POST" && deliveredId) {
      const actor = await authFromRequest(request, env, ["DRIVER","STAFF","OWNER"]);
      const rows = await supabaseFetch(env, `deliveries?id=eq.${encodeURIComponent(deliveredId)}&select=id,order_id`);
      if (!rows.length) throw new Error("DELIVERY_NOT_FOUND");
      await supabaseFetch(env, `deliveries?id=eq.${rows[0].id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ status: "DELIVERED", delivered_at: new Date().toISOString(), updated_at: new Date().toISOString() }),
      });
      await supabaseFetch(env, `orders?id=eq.${rows[0].order_id}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ status: "OWNER_PENDING", completed_at: new Date().toISOString(), updated_at: new Date().toISOString() }),
      });
      await audit(env, actor, "DELIVERY_COMPLETED", "delivery", deliveredId);
      return response({ ok: true }, 200, request);
    }

    // Daily report
    if (method === "GET" && path === "/api/reports/daily") {
      await authFromRequest(request, env, ["OWNER","STAFF"]);
      const date = url.searchParams.get("date") || new Date().toISOString().slice(0,10);
      const orders = await supabaseFetch(
        env,
        `orders?created_at=gte.${date}T00:00:00Z&created_at=lt.${date}T23:59:59Z&status=not.in.(CANCELLED)&select=id,order_no,total,status,fulfillment,created_at`
      );
      const total = orders.reduce((s, o) => s + Number(o.total || 0), 0);
      return response({
        ok: true,
        date,
        orders,
        summary: {
          orders: orders.length,
          revenue: total,
        }
      }, 200, request);
    }

    // EOD financial lock
    if (method === "POST" && path === "/api/financial/close") {
      const actor = await authFromRequest(request, env, ["OWNER"]);
      const body = await bodyJson(request);
      const ledgerDate = body.ledger_date || new Date().toISOString().slice(0,10);

      const existing = await supabaseFetch(
        env,
        `daily_ledger?ledger_date=eq.${ledgerDate}&select=*`
      );
      if (existing?.[0]?.locked) throw new Error("LEDGER_ALREADY_LOCKED");

      const orders = await supabaseFetch(
        env,
        `orders?created_at=gte.${ledgerDate}T00:00:00Z&created_at=lt.${ledgerDate}T23:59:59Z&status=not.in.(CANCELLED)&select=id,total`
      );
      const expected = orders.reduce((s,o) => s + Number(o.total || 0), 0);
      const cash = Number(body.cash_amount || 0);
      const mobile = Number(body.mobile_amount || 0);
      const actual = cash + mobile;
      const units = Number(body.total_units || 0);

      const payload = {
        ledger_date: ledgerDate,
        total_units: units,
        cash_amount: cash,
        mobile_amount: mobile,
        expected_revenue: expected,
        actual_revenue: actual,
        variance: actual - expected,
        closed_by: Number(actor.telegram_id),
        closed_at: new Date().toISOString(),
        locked: true,
      };

      const rows = await supabaseFetch(env, "daily_ledger", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=representation" },
        body: JSON.stringify(payload),
      });
      await audit(env, actor, "DAILY_LEDGER_CLOSED", "daily_ledger", ledgerDate, payload);
      return response({ ok: true, ledger: rows?.[0] || payload }, 200, request);
    }

    return response({ ok: false, error: "NOT_FOUND" }, 404, request);
  } catch (err) {
    const msg = err?.message || "INTERNAL_ERROR";
    let status = 500;
    if (["UNAUTHORIZED","TOKEN_INVALID","TOKEN_EXPIRED","TELEGRAM_AUTH_INVALID","TELEGRAM_INIT_DATA_EXPIRED"].includes(msg)) status = 401;
    else if (["FORBIDDEN"].includes(msg)) status = 403;
    else if (["NOT_FOUND","PRODUCT_NOT_FOUND","ORDER_NOT_FOUND","PAYMENT_NOT_FOUND","STAFF_NOT_FOUND","DELIVERY_NOT_FOUND"].includes(msg)) status = 404;
    else if (["INVALID_JSON","ITEMS_REQUIRED","ITEMS_REQUIRED","SKU_AND_NAME_REQUIRED","TELEGRAM_ID_AND_NAME_REQUIRED","DRIVER_ID_REQUIRED","ORDER_EMPTY","INVALID_QUANTITY","INSUFFICIENT_STOCK"].some(x => msg.startsWith(x))) status = 400;
    return response({ ok: false, error: msg }, status, request);
  }
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "INTERNAL_ERROR" }), {
        status: 500,
        headers: { ...JSON_HEADERS, ...corsHeaders(request) },
      });
    }
  }
};
