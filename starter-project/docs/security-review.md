# Security review SecureLab (ЛР 6)

> Рівень «Добре». Усі значення взято з власних запусків 19.11.2026. Без паролів, cookie, токенів.

## 1. Executive summary

Перевірено стан v0.5.0 (`bd636b1`) і виправлення в commit H1 `7e6a20c` (гілка `lab/6-hardening-review`) у локальному запуску на http://localhost:5080. У межах: клієнт, API, PostgreSQL, конфігурація, журнали, залежності. Поза межами: див. threat-model.md. Зафіксовано 2 findings, виправлено 2 (F-01 CSRF на cookie-змінювальних маршрутах, F-02 відсутні заголовки безпеки на відповіді 500). Додано rate limiting для пошуку, аудит успішного переходу статусу й нормалізацію логу. Regression на гілці після останньої зміни коду: PASS, 47 з 47, 19.11.2026; на merge commit M `cbe7903`: PASS, 47 з 47, 19.11.2026. Головні залишкові ризики: login CSRF, токен доступний XSS на власному origin, анонімний пошук за контрактом ЛР 1–2, відсутній доказ TLS/HSTS, in-memory limiter.

## 2. Scope та exclusions

Див. docs/threat-model.md (розділи 2 і 9).

## 3. System overview і trust boundaries

Див. docs/threat-model.md (розділи 6–7).

## 4. Methodology і test environment

Windows 11, PowerShell, Chrome (звичайне вікно = Alice, приватне = Morgan), .NET SDK 10.0.401, PostgreSQL 18.4 у контейнері (127.0.0.1:54329). Профілі: Development і Production-like (`--no-launch-profile -c Release`, `ASPNETCORE_ENVIRONMENT=Production`, підтверджено рядком `Hosting environment: Production`). Клієнти доказів: браузер, `curl.exe`/PowerShell, xUnit. Reset: `dotnet run --project src/SecureLab.Api -- --reset-database` (відмовляє поза Development: `InvalidOperationException`). Акаунти навчальні: Alice (Reporter), Morgan (Analyst), Admin; пароль береться зі змінної `SeedUsers__Password`.

## 5. Findings summary

| ID | Finding | Asset | Impact | Likelihood |
|---|---|---|---|---|
| F-01 | Cookie-автентифіковані змінювальні маршрути без antiforgery | стан інцидентів, сеанс | зміна стану від імені користувача зі стороннього origin (відтворено: `New → Triaged`) | помірна: потрібен активний сеанс і відкрита чужа сторінка |
| F-02 | Заголовки безпеки зникають на відповіді 500 | браузерні захисні заголовки | послаблення defense in depth на помилковому шляху | низька: потрібна неочікувана помилка сервера |

| ID | Priority | Status | Retest / регресія |
|---|---|---|---|
| F-01 | P1 | Fixed | REG-CSRF-01 |
| F-02 | P3 | Fixed | `UnexpectedError_Returns500_WithSecurityHeaders_AndNoInternals` |

Чому F-01 раніше за F-02: F-01 єдина знахідка, що дозволяє стороннім сторінкам змінювати дані від імені користувача, який ввійшов (відтворено), тоді як F-02 лише послаблює додатковий шар захисту й нічого не змінює без дії користувача. Виправлення F-01 також зачіпає найбільше коду й клієнта, тому його перевірено першим.

## 6. Detailed findings

docs/findings/F-01-csrf-cookie-mutations.md, docs/findings/F-02-security-headers-on-500.md.

## 7. Regression results

| ID | Property | Передумови | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|
| T-02 (ЛР 2) | server validation | reset, login, токен | порожній DTO → 400 з ключами полів | High з описом 40 символів → 201 | `Lab02ValidationTests.Create_WithEmptyDto_Returns400WithAllFieldKeys`, `Create_HighSeverityWithDescriptionAt40_Returns201` | pass |
| S-02 (ЛР 2) | SQL-структура не змінюється | seed | SQLi-ввід → порожня вибірка | пошук USB → 1 seed-запис | `Search_WithSqlInjectionPayload_ReturnsEmptySet`, `Search_WithUsbQuery_ReturnsSingleSeededRecord` | pass |
| A-* (ЛР 3) | authentication | акаунти seed | невідомий користувач і хибний пароль дають однаковий результат; анонім → 401 | login → `/api/me`; logout → 401 | `Login_UnknownUserAndWrongPassword_SameExternalResult`, `Create_Anonymous_Returns401NotRedirect`, `Login_ThenGetMe_ReturnsVerifiedCurrentUser`, `Logout_ThenProtectedRequest_Returns401` | pass |
| A-* (ЛР 4) | authorization/IDOR | Alice/Bob/Morgan | Reporter читає чужий інцидент → 403; Reporter triage → 403, статус не змінено | власний → 200; Analyst triage дозволено | `A03_Reporter_ReadsForeignIncident_Returns403WithoutData`, `A06_Reporter_Triage_Returns403_StatusUnchanged`, `A02_Owner_ReadsOwnIncident_Returns200`, `A07_Analyst_Triage_Allowed_ThenSecondAttemptConflicts` | pass |
| REG-XSS-01 | text не виконується | alice, інцидент `…0001` з marker-payload | `<img onerror=…>` як текст; marker `data-lab05-marker` не виставлено | звичайний текст картки | браузер: `GET: 200`, marker `null`; `ClientScript_DoesNotUseDangerousInnerHtmlSink` | pass |
| REG-CORS-01 | exact origin | probe 4173/4174 | Origin 4174: без `Access-Control-*` | Origin 4173: `Allow-Origin` і `Allow-Credentials` | `curl.exe -sS -D - -o NUL -H "Origin: …" http://localhost:5080/health` | pass |
| REG-CSRF-01 | пара токенів потрібна | login, reset | без/хибний токен: 400, стан не змінено | валідна пара: 200 | `RegCsrf01_Triage_…`, `RegCsrf01_Perimeter_EveryMutationWithoutToken_Returns400`, `Anonymous_Mutation_Returns401_NotAntiforgery400` | pass |
| rate limit login | abuse flow limited | quota/window | вище квоти: 429 | відновлення | `Login_AfterPermitLimit_Returns429AndRecoversAfterWindow` | pass |
| rate limit search | abuse flow limited | quota 3 за 10 с (дослід), default 20/30 с | 4-й запит: 429 | інший partition, відновлення | `Search_RateLimit_PartitionsAreIndependent_429_AndRecovers` + ручний дослід | pass |

Final run: `dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release` після `--reset-database`, 19.11.2026: total 47, failed 0, succeeded 47 (на гілці, H1 `7e6a20c`). Прогін на merge commit M `cbe7903` у `main` (після `--reset-database`, Release): total 47, failed 0, succeeded 47, 19.11.2026.

## 8. Hardening controls

| Control | Ризик | Verification | Межа |
|---|---|---|---|
| antiforgery token + cookie | CSRF | REG-CSRF-01 | не зупиняє XSS на тому ж origin; login/register без токена |
| server-side authorization | IDOR/BOLA | A-* (ЛР 4) | не замінює authentication |
| safe errors + traceId | витік деталей | контрольована 500 + журнал (збіг TraceId) | не замінює контроль доступу до логів |
| CSP + заголовки (в т.ч. на 500) | defense in depth | фактичні заголовки на 5 класах відповідей | не замінює safe DOM |
| rate limiting login/search | перебір, зловживання | тести 429, дослід двох partition | не замінює authn/authz; IP може бути спільним |
| audit triage (allowed/denied) | відстежуваність | записи `incident.status.changed` і `authorization.denied` | не є повним audit-сховищем |
| нормалізація недовіреного імені в журналі входу | log injection | `LogText.Safe` у login-журналі | лише цей sink |

### HTTPS і HSTS (лише запис)

- Профіль запуску: лише `http://localhost:5080` (`launchSettings.json`, рядок 8); HTTPS-профілю немає.
- У `src/SecureLab.Api` відсутні `UseHttpsRedirection()` і `UseHsts()` (перевірено `git grep -n -E "UseHttpsRedirection|UseHsts|applicationUrl" -- src/SecureLab.Api`).
- Реальний TLS, redirect на HTTPS, HSTS і deployment не тестувались.
- Відсутність HSTS на loopback дефектом не вважаємо.
- Для production окремо потрібні: TLS, `UseHttpsRedirection`, `UseHsts`, перевірка `Secure`-cookie. Це поза межами огляду.

## 9. Dependency and secret audit

### 9.1 Секрети (tracked files)

Команда: `git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .`
Кількість matches: 106. Шаблон навмисно широкий: більшість збігів є назвами полів, ключів і пакетів. Значення в таблиці не наводяться.

| Шлях:рядок | Контекст | Рішення |
|---|---|---|
| .gitignore:14 | коментар «Local configuration and secrets» | не секрет |
| README.md:63, 138 | текст про відкриті локальні значення і заборону реальних passwords | не секрет; тут же правило, що забороняє повторне використання |
| docs/browser-security-evidence.md:19 | назва змінної SeedUsers__Password, значення немає | не секрет |
| docs/git-workflow.md:124 | перелік того, що не комітити | не секрет |
| docs/security-review.md:66; docs/threat-model.md:27 | заголовок і назва активу | не секрет |
| src/SecureLab.Api/Client/auth-lab.html:15, 25 | поля форми type="password" | не секрет |
| src/SecureLab.Api/Client/auth-lab.js:56, 73 | очищення поля форми | не секрет |
| src/SecureLab.Api/Data/DbSeeder.cs:39, 42, 45, 49, 51, 53, 55, 183, 188, 190, 191, 209 | код читає ключ SeedUsers:Password, значення задають поза Git | не секрет; джерело конфігурації |
| src/SecureLab.Api/Data/Migrations/*:52, 194, 197, 210 | назва колонки PasswordHash, коментар | не секрет |
| src/SecureLab.Api/Scaffolding/Lab03Identity.cs:17, 88, 89, 102, 125, 136, 147, 152, 194–198, 205, 206 | політика паролів, DTO, тексти помилок | не секрет |
| tests/SecureLab.Api.Tests/*.cs (AuthenticationMechanicsTests:10–12; CookieClient:8, 14; IncidentEndpointTests:16–18, 24, 36, 46; Lab02ValidationTests:17–19, 24; Lab03AuthenticationScenarioTests:18–20, 122, 139, 160, 190, 217; Lab04AuthorizationTests:11, 21–23, 26) | пароль береться зі змінної середовища SeedUsers__Password | не секрет |
| tests/SecureLab.Api.Tests/Lab03AuthenticationScenarioTests.cs:29, 39, 48–50, 55, 63, 69, 83, 94, 132, 231, 236, 239, 242, 245, 248, 272 | тестові рядки для реєстрації й невдалого входу, не seed-пароль, використовуються для тимчасових акаунтів | accepted, study-only: тестові дані |
| tests/SecureLab.Api.Tests/packages.lock.json:208, 291 | назва пакета Microsoft.Extensions.Configuration.UserSecrets | не секрет, назва залежності |
| tests/http/lab-03-checks.http:3, 11, 14, 22, 33, 53, 62, 72, 90 | тіла тестових запитів | accepted, study-only: тестові дані |
| tests/http/lab-04-access.http:2, 16, 51, 61 | значення береться через processEnv зі змінної середовища | не секрет |
| src/SecureLab.Api/appsettings.Development.json:3 | відкритий навчальний пароль БД (securelab / local-study-password) | accepted, study-only |
| infra/compose.yaml:9 | той самий пароль контейнера PostgreSQL | accepted, study-only |
| src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs:10 | той самий connection string для design-time | accepted, study-only |

Три рядки accepted, study-only узгоджені між собою, їх не видаляють і не перейменовують: це зламає локальний стенд. Причини прийняття: README прямо забороняє повторне використання, БД прив'язана до 127.0.0.1, значення відкрите й навчальне. Рішення не поширюється на інші БД і середовища. Реального credential серед збігів не виявлено; у `infra/.env.example` збігів немає.

Межа висновку: перевірено поточні tracked files; історія, stash, інші клони й зовнішній CI не перевірялись. Порожній або чистий результат не доводить відсутності секретів в іншому стані.

Перегляд `git status --short` (лише `docs/*.md` змінено) і `git ls-files` (85 tracked files): перевірено всі поточні tracked files.

### 9.2 Залежності

SDK 10.0.401; команди `dotnet restore`, `dotnet package list --vulnerable --include-transitive`; дата 19.11.2026; код завершення 0. Результат: для `SecureLab.Api` і `SecureLab.Api.Tests` відомих advisory у прямих і транзитивних залежностях за джерелом nuget.org не знайдено. Межа: лише відомі на цю дату advisory цього джерела, досяжність не оцінювалась.

| Package | Version | Direct/transitive | Advisory/severity | Використовується? | Оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| Microsoft.OpenApi | 2.7.5 | direct (override transitive) | GHSA-v5pm-xwqc-g5wc | так (через Microsoft.AspNetCore.OpenApi) | вже застосовано | залишено: явний `PackageReference` піднімає транзитивну 2.x до виправленої версії; аудит не показує advisory |
| Microsoft.AspNetCore.OpenApi, Identity.EntityFrameworkCore, EntityFrameworkCore (+ .Relational) | 10.0.10 | direct | немає | так | не потрібне | залишено |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | direct | немає | так | не потрібне | залишено |
| Scalar.AspNetCore | 2.16.16 | direct | немає | лише Development | не потрібне | залишено |
| Microsoft.AspNetCore.Mvc.Testing, xunit, Microsoft.NET.Test.Sdk, coverlet.collector | 10.0.10; 2.9.3; 17.14.1; 6.0.4 | direct (тестовий проєкт) | немає | лише тести | не потрібне | залишено |

## 10. Residual risks

- login/register без antiforgery (login CSRF), токен доступний коду на власному origin (XSS);
- in-memory rate limiter не спільний між інстансами; IP може бути спільним;
- `AllowedHosts: "*"`; HTTP-only профіль, немає HTTPS/HSTS-доказу;
- сторонній UI /scalar у Development (на ньому CSP свідомо не ставиться);
- відкриті навчальні значення БД (`securelab` / `local-study-password`) у tracked files: accepted, study-only.

## 11. Conclusion

Огляд виявив одну суттєву знахідку (F-01, відсутність antiforgery на cookie-змінювальних маршрутах, відтворено й виправлено) і одну малу (F-02, заголовки безпеки на 500, виправлено). Додано rate limiting пошуку з розділенням за користувачем і IP, аудит успішного переходу статусу й нормалізацію логу. Регресія ЛР 2–5 і нові перевірки проходять (47 з 47 на гілці). Не закрито: login CSRF, анонімність пошуку за контрактом, відсутність доказу TLS/HSTS, in-memory limiter, сторонній UI /scalar. Результат справедливий лише для перевірених сценаріїв і локального стенда.

## 12. Evidence appendix

| ID | Що доводить | Де лежить / як повторити | Результат |
|---|---|---|---|
| EV-01 | Production-профіль, reset відмовляє поза Development | Рис. 3; запуск з `--no-launch-profile` | відмова `InvalidOperationException` |
| EV-02 | F-02 до виправлення: 500 без трьох заголовків | Рис. 4, 5; Таблиця 4 | заголовків немає |
| EV-03 | F-01 до виправлення: PoC зі 4174 | Рис. 8 | 200, `New → Triaged` |
| EV-04 | F-01 після виправлення | Рис. 9, 10, 11, 12 | 400 без токена, 200 з токеном |
| EV-05 | F-02 після виправлення | Рис. 13; Таблиця 7 | є 3 заголовки на 500 |
| EV-06 | rate limit login і search | Рис. 14, 15; Таблиця 8 | 429 і відновлення |
| EV-07 | залежності | Рис. 16 | немає відомих advisory |
| EV-08 | аудит triage, чистий журнал | Рис. 17, 18 | denied/allowed записи; 0/0/0 |
| EV-09 | повна регресія | Рис. 19 | 47 з 47 |
| EV-10 | Git-стани і тег | Рис. 20 | S/review-start `bd636b1` (v0.5.0), skeleton `fd896e3`, H1 `7e6a20c`, H2 `5749b07` + `eddbe16`, merge commit M `cbe790356214369498a19b3170e652ffda334ae6` (`cbe7903`), анотований тег `v1.0.0` на M |