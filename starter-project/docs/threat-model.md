# Межі огляду та модель загроз (ЛР 6, DEL-01)

> Заповнюється ФАКТАМИ. Рядки «ЗАПОВНИТИ» замінюєш значеннями з власних виводів.

## 1. Версія та середовище

| Елемент | Значення |
|---|---|
| review-start commit | bd636b1 |
| Гілка | lab/6-hardening-review |
| SDK | 10.0.401 |
| Профілі | Development (launchSettings, http://localhost:5080); production-like (--no-launch-profile, Release) |
| Дані | лише навчальні акаунти alice, bob, morgan, admin; reset: `dotnet run --project src/SecureLab.Api -- --reset-database` |

## 2. Компоненти в межах огляду

Браузерний клієнт (`src/SecureLab.Api/Client`), ASP.NET Core API (Minimal API), PostgreSQL (Docker Compose), конфігурація, журнали консолі, NuGet-залежності. Redis не використовується.

## 3. Активи

| Актив | Чому важливий |
|---|---|
| cookie сеансу `.AspNetCore.Identity.Application` | дає дії від імені користувача |
| інциденти (Title, Description, Comment.Text) | дані з обмеженим доступом (ЛР 4) |
| привілейований перехід Incident.Status (triage) | лише Analyst |
| журнал аудиту / IncidentStatusHistory | відстежуваність |
| configuration secrets | пароль seed-користувачів лише в змінній середовища |

## 4. Суб'єкти

anonymous; Reporter (alice, bob); Analyst (morgan); Administrator (admin); локальний розробник.

## 5. Entry points

ЗАПОВНИТИ з таблиці периметра (етап 2, п. 3): метод + маршрут для кожного змінювального маршруту, login, register, search, браузерні форми, завантаження конфігурації, restore пакетів, журнали.

## 6. Межі довіри та схема

```text
browser client (недовірений ввід, автоматична auth cookie)
       │ HTTP (local dev)
       ▼
ASP.NET Core API (validation, authn/authz, antiforgery, rate limiting, logging)
       │ connection string / EF Core
       ▼
PostgreSQL (дані застосунку)

repository + NuGet sources ──► restore/build
environment configuration  ──► API startup
```

## 7. Межа → очікувана властивість → перевірка

| Межа | Очікувана властивість | Перевірка (ID / команда) |
|---|---|---|
| browser→API | змінювальний запит із cookie без валідного токена відхилено, стан не змінено | REG-CSRF-01 (`Lab06HardeningTests`) |
| browser→API | текст користувача не виконується як код | REG-XSS-01 (ЛР 5) |
| browser→API | читання відповіді іншим origin обмежене allowlist | REG-CORS-01 (ЛР 5, повтор) |
| browser→API | пошук не можна викликати необмежено | Search_RateLimit… (`Lab06HardeningTests`) |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 (`Lab02ValidationTests`) |
| API→клієнт | 500 не розкриває stack trace; заголовки безпеки є і на 500 | UnexpectedError_Returns500… + ручний trace |
| repository→build | tracked files без реальних credentials; lockfile не змінюється непомітно | git grep (етап 1, п. 3); dotnet restore |
| environment→config | у Production не діє Development-конфігурація; reset заборонено | Hosting environment: Production + відмова --reset-database |

## 8. Наявні controls

validation (ЛР 2), authentication і rate limit login (ЛР 3), authorization IncidentAccess (ЛР 4), safe DOM renderText + CORS + CSP + заголовки (ЛР 5), antiforgery + search limiter + заголовки на error-path (ЛР 6).

## 9. Виключення (чого не перевіряли)

- немає production host, TLS-термінації, HSTS на реальному домені;
- не виконувався зовнішній penetration test;
- history Git, stash, інші клони, зовнішній CI не скануються (ЗАПОВНИТИ, якщо межі інші);
- `GET /api/incidents/search` і `/severity-summary` анонімні за контрактом ЛР 1–2: це прийняте обмеження, питання до викладача (див. Residual risks);
- login/register без antiforgery: токен видається лише після входу (login CSRF — залишковий ризик);
- Redis і advanced variant не входять до рівня «Добре».
