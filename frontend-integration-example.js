// Minimal integration for your existing Telegram Mini App.
// Put this in your frontend and replace API_BASE after deploying the Worker.

const API_BASE = "https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev";

async function soyamLogin() {
  Telegram.WebApp.ready();
  Telegram.WebApp.expand();

  const initData = Telegram.WebApp.initData;

  const response = await fetch(`${API_BASE}/api/auth/me`, {
    headers: {
      "X-Telegram-Init-Data": initData
    }
  });

  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Login failed");

  // Store in memory for the current SPA session.
  window.soyamSession = {
    token: data.token,
    user: data.user
  };

  return data;
}

async function soyamApi(path, options = {}) {
  if (!window.soyamSession?.token) await soyamLogin();

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${window.soyamSession.token}`,
      ...(options.headers || {})
    }
  });

  if (response.status === 401) {
    window.soyamSession = null;
    await soyamLogin();
    return soyamApi(path, options);
  }

  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "API request failed");
  return data;
}

// Examples:
// const products = await soyamApi("/api/products");
// const orders = await soyamApi("/api/orders");
// const inventory = await soyamApi("/api/inventory");
//
// await soyamApi("/api/orders", {
//   method: "POST",
//   headers: { "Idempotency-Key": crypto.randomUUID() },
//   body: JSON.stringify({
//     fulfillment: "DELIVERY",
//     delivery_address: "Addis Ababa ...",
//     customer_name: "Customer",
//     customer_phone: "+251...",
//     delivery_fee: 100,
//     items: [{ product_id: "PRODUCT_UUID", quantity: 1 }]
//   })
// });
