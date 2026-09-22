# Карта архітектури

Документ описує систему після ЛР 1 і один змінений маршрут: підсумок інцидентів за severity.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| ASP.NET Core API | `Presentation/`, `Application/` | Обирає endpoint за method і URL, перевіряє вхід, виконує сценарій, формує HTTP-відповідь |
| EF Core | `Data/` | Відображає C#-сутності на PostgreSQL через Npgsql, будує параметризовані запити |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері Docker Compose |

## Змінений маршрут: `GET /api/incidents/severity-summary`

```text
кнопка «Показати підсумок» у Client/index.html
  → loadSeveritySummary у Client/app.js
  → GET /api/incidents/severity-summary[?status=...]
  → IncidentEndpoints.GetSeveritySummaryAsync (перевірка status за allowlist)
  → IncidentQueries.GetSeveritySummaryAsync
  → SecureLabDbContext.Incidents / таблиця incidents
  → IncidentSeveritySummaryResponse як JSON
  → textContent у списку підсумку
```

Ключові файли:

| Рівень | Файл |
|---|---|
| Клієнт | `Client/index.html`, `Client/app.js` |
| Endpoint | `Presentation/Endpoints/IncidentEndpoints.cs` |
| Application | `Application/Incidents/IncidentQueries.cs` |
| DTO | `Presentation/Contracts/IncidentResponses.cs` |
| DbContext | `Data/SecureLabDbContext.cs` (`DbSet<Incident> Incidents`, `ToTable("incidents")`) |
| Сценарії перевірки | `tests/http/incidents.http`, `tests/SecureLab.Api.Tests/IncidentEndpointTests.cs` |

## Контракт та рішення

- Відповідь `200` містить JSON-масив елементів `{ severity, count }`; `description`, ідентифікатор власника, email і коментарі не повертаються.
- Політика нульових груп: лише наявні групи. На baseline seed відповідь містить High, Medium, Low по одному інциденту, Critical відсутній. Для статусу без інцидентів повертається `[]`.
- Порядок: від критичного до низького (Critical, High, Medium, Low). `Severity` зберігається як текст, тому SQL-сортування за ключем групи було б лексикографічним (High, Low, Medium); порядок задається після матеріалізації агрегату за значенням enum.
- Необов'язковий параметр `status` перевіряється за явним allowlist (New, Triaged, InProgress, Resolved, Closed, без урахування регістру). Значення поза переліком дає `400` Validation Problem Details.
- Query пише структурований log зі статусом фільтра та кількістю груп; описи інцидентів і конфігурація до журналу не потрапляють.

## Межі довіри

| Межа | Дані, що її перетинають | Чому даним ще не можна довіряти | Де перевіряємо або обмежуємо |
|---|---|---|---|
| Користувач → Browser client | значення `<select>`, натискання кнопки | Обмеження `<select>` діє лише в цьому UI | Клієнт формує URL через `encodeURIComponent`, але контролем безпеки не є |
| Browser client → API | method, URL, query `status`, path `id` | Будь-який HTTP-клієнт може надіслати запит без форми й кнопки | Allowlist для `status` у `IncidentEndpoints`; обмеження `:guid` та 404 для `id` |
| API → PostgreSQL | значення фільтра, умови запиту | Збережений або переданий текст не є автоматично безпечним | Параметризація EF Core, `AsNoTracking()`, явна проєкція в DTO |
| API → Browser | JSON з полями response DTO | Право читати сутність не означає право одержати всі її поля | Окремі response DTO без `OwnerUserId`, email і внутрішніх коментарів |
| Дані response → DOM | `severity`, `count`, `title`, `description` | Текст із БД міг бути користувацьким вводом | `textContent` і `document.createTextNode`; тест `ClientScript_DoesNotUseDangerousInnerHtmlSink` |
| Конфігурація → API | connection string | Локальна конфігурація не придатна для іншого середовища | `ConnectionStrings__SecureLab` поза Git; `infra/.env` ігнорується `.gitignore` |

## Конфігураційні входи

- `global.json` – версія .NET SDK та політика `rollForward`;
- `src/SecureLab.Api/appsettings.json` і `appsettings.Development.json` – режим міграцій і локальний connection string для Development;
- `infra/compose.yaml` – образ PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` – перевизначення connection string поза репозиторієм.

Реальні значення в документі не наводяться.

## Повернення до відомого стану

Зупинити API (`Ctrl+C`) і виконати:

```bash
dotnet run --no-build --project src/SecureLab.Api -- --reset-database
```

Команда застосовує migrations, очищує лише відомі навчальні таблиці й повторно заповнює їх seed-даними. Вона працює лише в явно налаштованому Development environment і після виконання не запускає API.
