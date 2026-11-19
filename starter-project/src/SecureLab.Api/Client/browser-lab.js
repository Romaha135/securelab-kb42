let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");
// Єдиний безпечний helper для Description і текстів коментарів:
// структуру елементів задає код, а дані потрапляють лише в текстовий вузол.
function renderText(container, value) {
  container.replaceChildren(document.createTextNode(String(value ?? "")));
}
async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  status.textContent = `GET: ${response.status}`;
  if (!response.ok) return;
  current = await response.json();
  document.querySelector("#title").textContent = current.title;
  renderText(document.querySelector("#description"), current.description);
  document.querySelector("#comments").replaceChildren();
  for (const comment of current.comments ?? []) {
    const paragraph = document.createElement("p");
    renderText(paragraph, comment.text);
    document.querySelector("#comments").append(paragraph);
  }
  document.querySelector("#edit").elements.description.value = current.description;
}
document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
  event.preventDefault();
  const payload = JSON.stringify({ title: event.currentTarget.elements.title.value,
    description: event.currentTarget.elements.description.value,
    severity: "Low", occurredAtUtc: new Date().toISOString() });
  let response;
  try {
    // ЛР 6: змінювальний запит іде через спільний helper, який додає antiforgery header.
    response = await window.SecureLabCsrf.mutate("/api/incidents", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
  } catch (error) {
    status.textContent = `POST: ${error.status ?? "помилка токена"}`;
    return;
  }
  status.textContent = `POST: ${response.status}`;
  if (response.ok) {
    const created = await response.json();
    document.querySelector("#incident-id").value = created.id;
    await load();
  }
});
