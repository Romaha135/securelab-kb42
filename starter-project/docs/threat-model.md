# Межі огляду та модель загроз (ЛР 6, DEL-01)


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

### 5.1 Змінювальні маршрути (за `git grep`, стан v0.5.0)

| Метод і маршрут | Що змінює | Authn | Antiforgery до виправлення |
|---|---|---|---|
| `POST /api/incidents` | створює інцидент | cookie-сесія | ні |
| `PUT /api/incidents/{id}` | змінює заголовок і опис | cookie-сесія | ні |
| `DELETE /api/incidents/{id}` | видаляє інцидент | cookie-сесія | ні |
| `POST /api/incidents/{id}/triage` | перехід `New` → `Triaged` | cookie-сесія | ні |
| `POST /api/auth/logout` | завершує сеанс | cookie-сесія | ні |
| `POST /api/auth/login` | створює сеанс | анонімний | н/д |
| `POST /api/auth/register` | створює обліковий запис | анонімний | н/д |

Решта маршрутів лише читає дані. Інших `MapPost`, `MapPut`, `MapPatch`, `MapDelete` у `src/SecureLab.Api` немає.

### 5.2 Інші точки входу

| Точка входу | Опис |
|---|---|
| `GET /api/incidents/search` | пошук; приймає текст від користувача; після Lab 6 обмежений rate limiting (політика `search`) |
| `GET /api/incidents`, `GET /api/incidents/{id}` | читання списку та картки; параметр `status` проходить валідацію |
| `POST /api/auth/login` | єдина точка входу для облікових даних; обмежена rate limiting (політика входу) |
| Браузерні форми | `browser-lab.html`, `auth-lab.html`: введення guid, назви та опису інциденту, облікових даних |
| `GET /api/csrf-token` | видає antiforgery-токен лише автентифікованому користувачу (додається в Lab 6) |
| Статичні сторінки клієнта | `GET /` та файли `Client/*`; також fallback для невідомих шляхів (`/scalar/v1` повертає сторінку клієнта) |
| Завантаження конфігурації | `appsettings.json`, змінні середовища (`ConnectionStrings__SecureLab`, `SeedUsers__Password`, `RateLimiting__*`), локальні `.env` та `appsettings.Local.json` (поза Git) |
| Restore пакетів | NuGet restore під час збирання; перевіряється аудитом залежностей (`dotnet package list --vulnerable --include-transitive`) |
| Журнали | вхідні дані користувача (ім'я користувача, ідентифікатори) потрапляють у журнал; очищаються через `LogText.Safe` |
| Аргументи запуску | `--reset-database`; дозволений лише в Development, інакше `InvalidOperationException` |

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

## 9. Виключення (чого не перевіряв)

- немає production host, TLS-термінації, HSTS на реальному домені;
- не виконувався зовнішній penetration test;
- history Git, stash, інші клони, зовнішній CI не скануються (перевірка секретів охоплює відстежувані файли робочого дерева: 85 файлів);
- login/register без antiforgery: токен видається лише після входу (login CSRF — залишковий ризик);
- Redis і advanced variant не входять до рівня «Добре».
