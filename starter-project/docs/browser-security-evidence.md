# Докази безпеки браузера (DEL-01)

Рівень: добрий («Добре»). Рівні накопичувальні, тому заповнено розділи «Для всіх» і «Добре». Паролі, cookie/token values та export browser storage не записуються.

## Стенд і Git-стан (Для всіх)

ОС, browser/version, API/probe origins: Windows 11 Pro, Chrome 157.0.8103.3; API http://localhost:5080, allowed probe http://localhost:4173, disallowed probe http://localhost:4174.
Release/base_commit/entry_parent з receipt: release lab-05-start-v1 (inherits v0.4.0); base_commit = entry_parent = e984f4514d15a5be201f8bc45d9b3d4bd190d2ef.
Vulnerable hash: 8c5bcda. Seed: 65f8d2c. Виправлення XSS (C1): e122acc. CORS (C2), fixed, v0.5.0, main і спосіб передавання: допишу пізніше.

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080): назва cookie [ЗАПОВНИ з DevTools], Domain [ЗАПОВНИ], Path [ЗАПОВНИ], HttpOnly так (за ЛР 3, перевір у DevTools), SameSite Lax (за ЛР 3, перевір у DevTools), Secure [ЗАПОВНИ: стенд працює по HTTP]. Value не записується.

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: textarea description у формі #edit (browser-lab.html) → browser-lab.js, POST /api/incidents (JSON-поле description) → перевірка на сервері (обов'язкове, до 4000 символів, Trim) → Incident.Description у PostgreSQL → GET /api/incidents/{id}, поле description → browser-lab.js, функція load() → sink: #description.innerHTML = current.description. Докладна таблиця: docs/source-to-sink.md.

Гіпотеза: значення з textarea description зберігається в PostgreSQL (Incident.Description), повертається через JSON-поле description і передається в #description.innerHTML як HTML-контекст; тому, якщо користувач контролює опис, браузер може розібрати дані не як звичайний текст.

Передумови: commit 8c5bcda (vulnerable), база скинута командою dotnet run --project src/SecureLab.Api -- --reset-database, API запущено командою dotnet run --project src/SecureLab.Api, пароль seed-користувачів у змінній середовища SeedUsers__Password. Локальний користувач: alice (Reporter), для читання: morgan (Analyst), контроль: bob (Reporter, чужий запис).

Guid запису: 2480eca0-28df-4013-806a-0340a67eeb19. Marker: канонічний, з resources/lab05-marker.txt (змінює лише атрибут data-lab05-marker на прихованому #lab05-marker-target).

Create/read: Alice на /browser-lab.html вставляє marker в опис, натискає «Створити й прочитати» (POST 201, GET 200). Morgan відкриває той самий Guid; перевірка в Console document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker") повертає null до і 'executed' після читання. Bob: 403 і null.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | description = marker без змін (desc-before.json) | description збігається з «до» (PowerShell: True) | Рис. 7, 13 |
| DOM основного Description | img src="x" onerror=… у #description | один текстовий вузол, marker видно як текст | Рис. 8, 13 |
| Дія marker | перевірка: null до, 'executed' після | перевірка Console: null | Рис. 8, 13 |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | 1–3 без змін; 4: b розібрано як тег, слово жирним; …03: видно лише «Текст» | усе як текст; текст з тегом b видно з дужками; …03 видно повністю | Рис. 6, 14 |
| Довжина за власними правилами ЛР 2 | 3900 символів збережено й показано повністю, textContent.length = 3900 | 3900 символів, textContent.length = 3900 | Рис. 6, 14 |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan: GET 200, 'executed'; Bob: GET 403, null | коментар у вікні Morgan: null | Рис. 9, 15 |

Finding: Актив: сеанс користувача й дані, доступні від його імені. Передумови: локальний акаунт і контроль над текстовим полем опису. Першопричина: недовірений рядок з API передається в innerHTML (HTML-контекст). Вплив на стенді: marker, створений Alice, виконався в сеансі Morgan (Analyst) і змінив лише тестовий елемент #lab05-marker-target; Bob отримав 403, код у його сеансі не виконувався. Safe DOM diff: у browser-lab.js додано renderText (replaceChildren + createTextNode), два присвоєння innerHTML замінено її викликами, commit e122acc (Рис. 12). Retest: той самий marker показано як текст, один текстовий вузол, перевірка null, значення в API не змінилось. Залишковий ризик: інші поля й sink-и, сторонні скрипти, CSRF (ЛР 6).

Повторювана REG-XSS-01: передумови: fixed commit (hash допишу після тегу), reset бази, локальні alice і morgan; вхід: marker з resources/lab05-marker.txt; кроки: Alice створює інцидент з marker в описі, Alice і Morgan відкривають його; очікування: у #description один текстовий вузол, перевірка Console повертає null, звичайні рядки (апостроф, лапки, 5 < 7, Unicode, текст з тегом b, довгий текст) показано як текст; негативний контроль: на vulnerable commit 8c5bcda той самий marker виконується ('executed').

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнено до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | один origin, CORS не потрібен |
| simple GET 4173 → API | так, запит доходить | ні, поки відповідь не містить Access-Control-Allow-Origin | браузер блокує читання відповіді чужого origin (SOP/CORS) |
| simple GET 4174 → API | так, запит доходить | ні | те саме: дозволу в відповіді немає |
| curl/.http → API | так | не застосовується | це не JavaScript у браузері, SOP/CORS не діє |
| preflighted 4173 → API («Добре / Відмінно») | спершу лише OPTIONS; actual GET — лише після успішного preflight | ні, доки немає успішного preflight і дозволу | нестандартний заголовок X-Lab-Cors-Probe змушує браузер надіслати preflight |

Команди запуску probes: py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe і py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe (у різних терміналах, з кореня проєкту). Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без AllowCredentials().

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | | | |
| Allowed 4173 | | | |
| Disallowed 4174 | | | |
| Direct HTTP / curl | | | |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: публічний seed-коментар 30000000-0000-0000-0000-000000000005 (is_internal = false, автор Morgan) в інциденті 20000000-0000-0000-0000-000000000001, текст = marker; додано окремим commit-ом 65f8d2c (DbSeeder.cs). DOM до: img src="x" onerror=… у #comments, Console 'executed' (Рис. 11). DOM після: текстовий вузол у відповідному p, Console null у вікнах Alice і Morgan (Рис. 15). Єдиний safe helper і виклики для обох полів: renderText(container, value) у browser-lab.js; виклики renderText(#description, current.description) і renderText(paragraph, comment.text), commit e122acc.

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: … Кінцевий AllowCredentials() — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення new Image() до 4173 — результат: … Для «Добре» докази report-only не обов'язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |