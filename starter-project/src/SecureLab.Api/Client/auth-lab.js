// Той самий прийом, що й api-fetch.js (resources/browser) методички: cookie надсилається
// лише на свій origin, зовнішня адреса відхиляється ще до fetch.
async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

const sessionStateElement = document.querySelector("#session-state");
const registerResult = document.querySelector("#register-result");
const loginResult = document.querySelector("#result");
const profileElement = document.querySelector("#profile");
const createResult = document.querySelector("#create-result");

async function refreshSessionState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    if (response.status === 204) {
      sessionStateElement.textContent = "активний";
    } else if (response.status === 401) {
      sessionStateElement.textContent = "анонімний";
    } else {
      sessionStateElement.textContent = "невідомий";
    }
  } catch {
    sessionStateElement.textContent = "невідомий";
  }
}

async function describeProblem(response) {
  const contentType = response.headers.get("Content-Type") ?? "";
  if (!contentType.includes("application/problem+json")) {
    return `${response.status}`;
  }
  const problem = await response.json();
  if (problem.errors) {
    const fields = Object.entries(problem.errors)
      .map(([field, messages]) => `${field}: ${messages.join(" ")}`)
      .join("\n");
    return `${response.status} ${problem.title}\n${fields}`;
  }
  return `${response.status} ${problem.title ?? ""} ${problem.detail ?? ""}`.trim();
}

document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = Object.fromEntries(new FormData(form));
  const response = await apiFetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  form.elements.password.value = "";
  if (response.status === 201) {
    const created = await response.json();
    registerResult.textContent = `Зареєстровано: ${created.userName}. Тепер увійдіть нижче.`;
  } else {
    registerResult.textContent = await describeProblem(response);
  }
});

document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const response = await apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form)))
  });
  form.elements.password.value = "";
  loginResult.textContent = `Login: ${response.status}`;
  await refreshSessionState();
  if (response.status === 204) {
    await loadProfile();
  }
});

async function loadProfile() {
  const response = await apiFetch("/api/me");
  if (response.ok && (response.headers.get("Content-Type") ?? "").includes("application/json")) {
    const profile = await response.json();
    // Лише дозволені поля DTO, через textContent — без innerHTML.
    profileElement.textContent =
      `userId: ${profile.userId}\nuserName: ${profile.userName}\nrole: ${profile.role}`;
  } else if (response.status === 401) {
    profileElement.textContent = "Не ввійшли.";
  } else {
    profileElement.textContent = `Не вдалося завантажити профіль (${response.status}).`;
  }
}

document.querySelector("#me").addEventListener("click", loadProfile);

document.querySelector("#logout").addEventListener("click", async () => {
  await apiFetch("/api/auth/logout", { method: "POST" });
  profileElement.textContent = "";
  createResult.textContent = "";
  loginResult.textContent = "";
  await refreshSessionState();
  // Очищення UI саме по собі не доводить вихід — нижче те саме перевіряє сервер.
  const check = await apiFetch("/api/auth/session-check");
  loginResult.textContent = `Після logout session-check: ${check.status}`;
});

document.querySelector("#create-incident").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const occurredAtUtc = new Date(formData.get("occurredAtUtc")).toISOString();
  const body = {
    title: formData.get("title"),
    description: formData.get("description"),
    severity: formData.get("severity"),
    occurredAtUtc
  };
  const response = await apiFetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (response.status === 201) {
    const created = await response.json();
    createResult.textContent = `Створено: ${created.id}`;
    form.reset();
  } else if (response.status === 401) {
    createResult.textContent = "Спершу увійдіть.";
  } else {
    createResult.textContent = await describeProblem(response);
  }
});

refreshSessionState();
