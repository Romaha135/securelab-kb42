# Security review SecureLab (ЛР 6)

> ЗАПОВНИТИ = взяти значення з власного виводу. Нічого не вигадувати. Без паролів, cookie, токенів.

## 1. Executive summary

Перевірено commit ЗАПОВНИТИ (гілка lab/6-hardening-review) у локальному запуску на http://localhost:5080. У межах: клієнт, API, PostgreSQL, конфігурація, журнали, залежності. Поза межами: див. threat-model.md. Зафіксовано ЗАПОВНИТИ findings, виправлено ЗАПОВНИТИ. Final regression після останньої зміни: ЗАПОВНИТИ (PASS/FAIL, дата). Головні залишкові ризики: ЗАПОВНИТИ.

## 2. Scope та exclusions

Див. docs/threat-model.md (розділи 2 і 9).

## 3. System overview і trust boundaries

Див. docs/threat-model.md (розділи 6–7).

## 4. Methodology і test environment

ОС, браузер, SDK, профілі Development / Production-like, клієнти доказів (browser, curl.exe/PowerShell, xUnit), reset-команда, акаунти.

## 5. Findings summary

| ID | Finding | Asset | Impact | Likelihood |
|---|---|---|---|---|
| F-01 | Cookie-автентифіковані змінювальні маршрути без antiforgery | стан інцидентів, сеанс | ЗАПОВНИТИ | ЗАПОВНИТИ |
| F-02 | ЗАПОВНИТИ (заголовки безпеки зникають на 500 / або запасна F-03) | ЗАПОВНИТИ | ЗАПОВНИТИ | ЗАПОВНИТИ |

| ID | Priority | Status | Retest / регресія |
|---|---|---|---|
| F-01 | ЗАПОВНИТИ | Fixed | REG-CSRF-01 |
| F-02 | ЗАПОВНИТИ | Fixed | ЗАПОВНИТИ |

Чому F-01 раніше за F-02: ЗАПОВНИТИ (1–2 речення).

## 6. Detailed findings

docs/findings/F-01-*.md, F-02-*.md.

## 7. Regression results

| ID | Property | Передумови | Негативний сценарій | Позитивна перевірка | Evidence / command | Result |
|---|---|---|---|---|---|---|
| T-02 (ЛР 2) | server validation | reset, login, токен | недопустиме input | допустиме input | ЗАПОВНИТИ (`Lab02ValidationTests`) | ЗАПОВНИТИ |
| S-02 (ЛР 2) | SQL-структура не змінюється | seed | SQLi-ввід | пошук USB | ЗАПОВНИТИ | ЗАПОВНИТИ |
| A-* (ЛР 3) | authentication | акаунт | invalid login | login/logout | ЗАПОВНИТИ | ЗАПОВНИТИ |
| A-* (ЛР 4) | authorization/IDOR | Alice/Bob | чужий об'єкт | власний | ЗАПОВНИТИ | ЗАПОВНИТИ |
| REG-XSS-01 | text не виконується | marker | marker до/після | звичайний текст | ЗАПОВНИТИ | ЗАПОВНИТИ |
| REG-CORS-01 | exact origin | 4173/4174 | 4174 | 4173 | ЗАПОВНИТИ | ЗАПОВНИТИ |
| REG-CSRF-01 | пара токенів потрібна | login, reset | без/хибний токен: 400, стан не змінено | валідна пара: 200 | `RegCsrf01_*` | ЗАПОВНИТИ |
| rate limit login | abuse flow limited | quota/window | вище квоти: 429 | відновлення | `Login_AfterPermitLimit…` | ЗАПОВНИТИ |
| rate limit search | abuse flow limited | quota/window | 4-й запит: 429 | інший partition, відновлення | `Search_RateLimit…` | ЗАПОВНИТИ |

Final run: команда `dotnet test … --configuration Release`, дата, результат ЗАПОВНИТИ.

## 8. Hardening controls

| Control | Ризик | Verification | Межа |
|---|---|---|---|
| antiforgery token + cookie | CSRF | REG-CSRF-01 | не зупиняє XSS на тому ж origin |
| server-side authorization | IDOR/BOLA | A-* (ЛР 4) | не замінює authentication |
| safe errors + traceId | витік деталей | контрольована 500 + log | не замінює контроль доступу до логів |
| CSP + заголовки | defense in depth | фактичні заголовки на 5 класах відповідей | не замінює safe DOM |
| rate limiting login/search | перебір, зловживання | тести 429 | не замінює authn/authz; IP може бути спільним |
| audit triage | відстежуваність | лог allowed/denied | не є повним audit-сховищем |

## 9. Dependency and secret audit

### 9.1 Секрети (tracked files)
Команда і шаблон: ЗАПОВНИТИ. Кількість matches: ЗАПОВНИТИ. Таблиця `шлях:рядок → рішення`: ЗАПОВНИТИ.
Межа: перевірено поточні tracked files; history, stash, інші клони й зовнішній CI не перевірено.

### 9.2 Залежності
SDK, команда `dotnet package list --vulnerable --include-transitive`, дата, код завершення, вивід: ЗАПОВНИТИ.

| Package | Version | Direct/transitive | Advisory/severity | Використовується? | Оновлення | Рішення і причина |
|---|---|---|---|---|---|---|
| ЗАПОВНИТИ | | | | | | |

Окремо врахувати коментар у SecureLab.Api.csproj про явний override Microsoft.OpenApi (GHSA-v5pm-xwqc-g5wc).

## 10. Residual risks

- login/register без antiforgery (login CSRF), токен доступний коду на власному origin (XSS);
- `/api/incidents/search` і `/severity-summary` анонімні за контрактом ЛР 1–2 (питання до викладача);
- in-memory rate limiter не спільний між інстансами; IP може бути спільним;
- `AllowedHosts: "*"`; HTTP-only профіль, немає HTTPS/HSTS-доказу;
- сторонній UI /scalar у Development;
- ЗАПОВНИТИ (з фактичних спостережень).

## 11. Conclusion

ЗАПОВНИТИ.

## 12. Evidence appendix

| ID | Що доводить | Де лежить / як повторити | Результат |
|---|---|---|---|
| EV-01 | ЗАПОВНИТИ | ЗАПОВНИТИ | ЗАПОВНИТИ |

## Декларація та журнал використання ШІ

ЗАПОВНИТИ правдиво (сервіс, для чого використано, що перевірено й змінено власноруч).
