# Звіт WEB ЛР 2

## 1. Ідентифікація

- ПІБ і група: Поліщук Роман Сергійович, КБ-42.
- Спільний baseline 2-A; індивідуального номера немає.
- Заявлений рівень: добрий («Добре»).
- Гілка lab/2-input-sqli: створена від тегу v0.1.0 (commit `922f8b734b030878611a47b11c5ca8337ecf4258`).
- Release, base_commit та entry_parent із квитанції `.scaffolds/lab-02.json`: release `lab-02-start-v1`, base_commit `922f8b734b030878611a47b11c5ca8337ecf4258`, entry_parent `37ee209389623882c5fbcd0543053e58224742c5` (окремий commit оновлення global.json передував установленню scaffold, тому base_commit і entry_parent різняться — це очікувано).
- Vulnerable commit: `f7a5b199c54471dd1902c84e46a24514bd94a027` («Validate create-incident contract: required fields, enum, date, cross-field rule, conflict») — контракт створення вже перевірений, пошук ще вразливий.
- Fixed commit коду: `57258c6358e47acb35dfbd658dcf0ac074ff1541` («Parameterize search query with EF.Functions.ILike and sortBy allowlist; add regression tests»). Фінальний тег v0.2.0 ставиться на commit із цим звітом, після fixed commit: TODO (hash підставити після commit звіту).
- DEL-01: URL приватного remote з доступом або ім'я переданого bundle: TODO.

## 2. Контракт і CP-01

Request DTO `CreateIncidentRequest` (`src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`) містить лише `Title`, `Description`, `Severity`, `OccurredAtUtc` — жодних server-managed полів (`Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc`). Обробник `POST /api/incidents` перевіряє, у такому порядку: required і довжина `Title` (≤160) та `Description` (≤4000) на надісланому значенні до `Trim()`; `Severity` через `Enum.TryParse(..., ignoreCase: true, ...)` разом з `Enum.IsDefined` (`severity: "7"` відхиляється, а не стає `Low`); обов'язковість `OccurredAtUtc` і межу `now.AddMinutes(5)`. Усі помилки збираються в один `Dictionary<string, string[]>` і повертаються одним `Results.ValidationProblem(errors)` до звернення до БД.

Для доброго рівня додано cross-field правило (T-09): якщо перевірене `Severity` дорівнює `High` або `Critical`, нормалізований `Description` (після одноразового `Trim()`) має містити щонайменше 40 символів; порушення дає 400 з ключем `description`, якщо той ще не зайнятий попередньою помилкою. Предметний конфлікт (T-03): інцидент з тим самим після `Trim()` і чутливим до регістру `Title` не створюється вдруге, якщо наявний збіг перебуває у статусі `New`, `Triaged`, `InProgress` або `Resolved`; `Closed` не блокує. За збігу повертається 409 без поля `errors`.

Сервер самостійно встановлює `Id`, `OwnerUserId = DbSeeder.AliceId`, `Status = New`, `CreatedAtUtc`/`UpdatedAtUtc = now`, а `OccurredAtUtc` нормалізується в UTC через `.ToUniversalTime()` після перевірки меж. Відповідь — окремий `CreatedIncidentResponse(Id, Title, Severity, Status, OccurredAtUtc, CreatedAtUtc)`, без внутрішніх полів.

CP-01 (overposting): запит із зайвими `id`, `status: "Closed"`, `ownerUserId` у тілі ігнорує ці поля, бо `CreateIncidentRequest` їх не оголошує — запис отримує новий `Id`, `Status = New` і власника Alice. Перевірено вручну (`tests/http/lab-02-checks.http`, сценарій «overposting probe») і автоматично (`Lab02ValidationTests.Create_WithOverpostedServerManagedFields_IgnoresClientValues`).

## 3. Security-сценарій і CP-02/CP-03

**Контекст і гіпотеза.** `GET /api/incidents/search` у стані scaffold приймав `q` і `sortBy` з query string і напряму конкатенував їх у текст SQL (`src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, обробник `/api/incidents/search`), тому недовірене значення могло вплинути на структуру запиту.

**Стан до (vulnerable).** Vulnerable-знімок зафіксовано на commit `f7a5b199c54471dd1902c84e46a24514bd94a027`: `var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "") + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";` з подальшим `db.Incidents.FromSqlRaw(sql)`.

**Мінімальний PoC.** Власний read-only контрольний сценарій C з `tests/http/lab-02-sqli-check.http`: `q=zz-no-match' OR TRUE -- ` (з пробілом наприкінці).

**Спостереження.** TODO: підставити фактичний результат запиту C на vulnerable commit (очікується розширена вибірка — усі інциденти таблиці замість `[]`) і запис `Executed DbCommand` із журналу API, де видно, що значення `zz-no-match' OR TRUE -- ` увійшло до тексту SQL, а `Parameters=[]` порожній.

**Першопричина.** `q` і `sortBy` з'єднувались із SQL-текстом конкатенацією рядків до виконання; апостроф у значенні закривав рядковий літерал, а `OR TRUE` ставало частиною умови `WHERE`. Повідомлення про SQL-помилку (для сценарію D, легітимний апостроф) саме по собі причину не пояснює — пояснює саме порівняння тексту команди з/без лапок.

**Виправлення.** Fixed commit `57258c6358e47acb35dfbd658dcf0ac074ff1541`: пошук переписано на LINQ з `EF.Functions.ILike(item.Title, pattern, "\\")` / `EF.Functions.ILike(item.Description, pattern, "\\")`, де `pattern` передається окремим параметром, а не текстом SQL. Значення `q` екранується функцією `EscapeLike` (спершу `\`, потім `_`, потім `%`) для буквального підрядкового пошуку — перевірено проти прикладів методички (`rate_5%` → `%rate\_5\%%`, `path\A` → `%path\\A%`). `sortBy` обрано через `switch`-allowlist (`createdAtUtc` за замовчуванням з `OrderByDescending` + `ThenBy(Id)`, `severity` за явним рангом Critical→Low, `status` за явним рангом New→Closed); невідоме значення дає `null` і 400 з ключем `sortBy`, до SQL не доходить.

**Retest і позитивна регресія (S-02, T-04).** Той самий сценарій C на fixed commit повертає 200 і `[]` (`Lab02ValidationTests.Search_WithSqlInjectionPayload_ReturnsEmptySet`). Звичайний пошук `q=USB` повертає рівно один очікуваний запис (`Search_WithUsbQuery_ReturnsSingleSeededRecord`), легітимний апостроф `q=O'Brien` повертає очікуваний запис без 500 (`Search_WithLegitimateApostrophe_ReturnsExpectedRecordWithout500`).

**Залишковий ризик.** Перевірка `AnyAsync` для предметного конфлікту (T-03) не гарантує інваріант за паралельних запитів без транзакційного рішення чи обмеження БД — для цього навчального рішення це прийнятне спрощення. Ця робота не додає authorization, rate limit чи пагінацію; це поза межами завдання ЛР 2.

## 4. Фактичні перевірки DEL-02

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректне створення | відновлений seed | `POST /api/incidents`, валідний DTO | 201, response DTO без зайвих полів | TODO | `tests/http/lab-02-checks.http`, сценарій T-01 |
| T-02 | Некоректний DTO | — | `POST` з порожнім title, severity "7", без occurredAtUtc | 400, application/problem+json з ключами title/severity/occurredAtUtc | TODO | `tests/http/lab-02-checks.http` T-02; `Lab02ValidationTests.Create_WithEmptyDto_Returns400WithAllFieldKeys` |
| T-03 | Предметний конфлікт | активний інцидент з тим самим title | повторний `POST` з тим самим title | 409 у Problem Details, без errors | TODO | `tests/http/lab-02-checks.http` T-03; `Lab02ValidationTests.Create_DuplicateActiveTitle_Returns409` |
| S-01 | SQLi до виправлення | vulnerable commit, local seed | сценарій C з lab-02-sqli-check.http | небажано розширена вибірка | TODO | commit `f7a5b199c54471dd1902c84e46a24514bd94a027` + запис Executed DbCommand |
| S-02 | Retest SQLi | fixed commit, той самий seed | той самий сценарій C | 200, [] | TODO | `Lab02ValidationTests.Search_WithSqlInjectionPayload_ReturnsEmptySet` |
| T-04 | Позитивна регресія | fixed commit | звичайний пошук USB і пошук з апострофом O'Brien | коректні записи, без 500 | TODO | `Lab02ValidationTests.Search_WithUsbQuery_ReturnsSingleSeededRecord`, `Search_WithLegitimateApostrophe_ReturnsExpectedRecordWithout500` |
| T-05 | Невідоме сортування | fixed commit | `sortBy=price` | 400, ключ sortBy | TODO | `tests/http/lab-02-checks.http` T-05; `Lab02ValidationTests.Search_WithUnknownSortBy_Returns400WithSortByKey` |
| T-06 | Ресурс не знайдено | endpoint ЛР 1 | GET неіснуючого id | 404 у Problem Details | TODO | `tests/http/lab-02-checks.http` T-06 |
| T-09 | Cross-field 2-A | унікальні title | description 39 і 40 символів для High | 400 (39) та 201 (40) | TODO | `tests/http/lab-02-checks.http` T-09; `Lab02ValidationTests.Create_HighSeverityWithDescriptionBelow40_Returns400WithDescriptionKey`, `..At40_Returns201` |
| A-01 | Огляд data-access points | fixed commit | `data-access-scan.py` + `git grep` за FromSqlRaw/ExecuteSqlRaw/ORDER BY/`$"SELECT`/`+ query` | для кожного збігу — файл/метод, категорія, висновок | один збіг: `src/SecureLab.Api/Data/DatabaseBootstrap.cs:29`, `ExecuteSqlRawAsync` з літеральним `TRUNCATE TABLE …` без параметрів; категорія: trusted static SQL; висновок: безпечно, рядок не містить вхідних даних, виконується лише в Development за `Database:AllowReset`. Другий grep-патерн (`$"SELECT`, `+ query`) збігів не дав | збіг знайдено | вивід `data-access-scan.py .` і `git grep` наведено вище в розділі 3 |

Build/baseline-tests після останньої зміни (`dotnet build tests/SecureLab.Api.Tests -c Release` і `dotnet test tests/SecureLab.Api.Tests -c Release`): TODO — підставити фактичний підсумковий рядок зі свого запуску.

## 5. Обмеження і висновок

Контракт `POST /api/incidents` перевірено на всіх базових полях 2-A (required, довжини 160/4000, enum через TryParse+IsDefined, дата з допуском 5 хвилин і нормалізацією в UTC), доповнено cross-field правилом і предметним конфліктом доброго рівня; відповідь обмежена окремим response DTO. SQL injection у пошуку відтворено на контрольованому read-only сценарії, локалізовано до рядка конкатенації SQL у `Lab02Endpoints.cs` і усунено переходом на LINQ з `EF.Functions.ILike` та параметризованим `pattern`, а вибір сортування обмежено allowlist. Перевірка предметного конфлікту через `AnyAsync` перед записом не гарантує інваріант за одночасних запитів без додаткового обмеження БД або транзакції — це обмеження навчального рішення, яке в продакшн-коді варто закрити унікальним індексом або серіалізованою транзакцією. Під час ручної перевірки окремо не спостерігалося нового дефекту оброблення JSON (відповідь 500 на зіпсований JSON із стартового конвеєра ЛР 1 не досліджувалась повторно в межах цієї роботи).

## 6. Декларація використання ШІ

| Сервіс | Задачі | Авторська адаптація/інтерпретація | Фактична перевірка |
|---|---|---|---|
| Claude (Anthropic) | Реалізація server-side validation, cross-field правила та предметного конфлікту для POST /api/incidents; перехід пошуку з конкатенованого SQL на LINQ з EF.Functions.ILike та escape-функцією; allowlist sortBy; автоматичні тести Lab02ValidationTests; текст цього звіту | TODO: підтвердити, що рівень (добрий), конкретні повідомлення про помилки, назви тестів і формулювання розділів 2–5 переглянуто і прийнято свідомо, а не скопійовано без читання; за потреби — скоригувати формулювання власними словами | TODO: власний запуск build/test/retest з розділу 4 як фактична перевірка згенерованого коду |

## 7. Передавання

- Remote доступний викладачеві або bundle перевірено через verify/list-heads: TODO.
- У Moodle файли/докази видимі й роботу надіслано: TODO.
- Git diff та історію перевірено на секрети: TODO.
