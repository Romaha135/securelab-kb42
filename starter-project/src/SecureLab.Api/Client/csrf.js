// Спільний helper antiforgery для всіх сторінок клієнта (ЛР 6).
// Токен живе лише в пам'яті поточної сторінки; cookie браузер зберігає сам.
// Підключається ПЕРЕД скриптом сторінки (обидва defer зберігають порядок).
(() => {
  const HEADER_NAME = "X-SecureLab-CSRF";
  const TOKEN_URL = "/api/csrf-token";
  let token = null;
  let pending = null;
  let generation = 0;

  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  function failure(message, status) {
    const error = new Error(message);
    error.status = status;
    return error;
  }

  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch(TOKEN_URL, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) {
        throw failure(`Token request failed: ${response.status}`, response.status);
      }
      const data = await response.json();
      if (current !== generation) {
        throw failure("Session changed; request a fresh token.", 0);
      }
      if (typeof data.token !== "string" || !data.token) {
        throw failure("Invalid token response.", 0);
      }
      token = data.token;
      return token;
    })();
    pending = operation;
    try {
      return await operation;
    } finally {
      if (pending === operation) pending = null;
    }
  }

  // Усі змінювальні запити (POST/PUT/PATCH/DELETE) на свій origin ідуть через mutate().
  async function mutate(url, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      throw new Error("Use normal fetch for read requests.");
    }
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) {
      throw new Error("Token must stay on the same origin.");
    }
    const headers = new Headers(options.headers);
    headers.set(HEADER_NAME, await ensureToken());
    const response = await fetch(target, { ...options, method, headers, credentials: "same-origin" });
    // Після 400/401 токен забуваємо, але запит автоматично НЕ повторюємо (міг би створити дубль).
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = { reset, ensureToken, mutate };
  window.addEventListener("pageshow", reset);
})();
