# F-01. Змінювальні маршрути з cookie не вимагають antiforgery-токена

**Статус:** Fixed
**Актив:** стан інцидентів, сеанс користувача
**Компонент:** POST/PUT/DELETE з cookie-автентифікацією (create, update, delete, triage, logout)
**Пріоритет:** P1

## Передумови і межі огляду
Стан до виправлення: v0.5.0 (`bd636b1`); виправлення в H1 `7e6a20c` (гілка `lab/6-hardening-review`). Профіль Development, `http://localhost:5080`. Акаунти навчальні: Morgan (Analyst), Alice (Reporter). Стан скидається командою `dotnet run --project src/SecureLab.Api -- --reset-database`. Периметр: 7 змінювальних маршрутів (таблиця в threat-model.md, розділ 5). Поза межами: реальне розгортання, TLS, зовнішні сервіси.

## Відтворення (до виправлення)
1. reset, API запущено.
2. Morgan входить у приватному вікні (`Login: 204`).
3. З Console вкладки `http://localhost:4174`: `fetch("http://localhost:5080/api/incidents/20000000-0000-0000-0000-000000000005/triage", { method: "POST", credentials: "include", mode: "no-cors" })`.
4. Результат: у Network `POST …/triage` має статус 200 OK; відповідь для скрипта opaque (`status: 0`), проте читання інциденту `…0005` показує, що статус змінився з `New` на `Triaged` без жодного токена.

## Вплив і ймовірність
**Статус перевірки:** спостережено локально.
Стороння сторінка, відкрита в тому самому браузері, змінює стан від імені користувача, який ввійшов (на прикладі аналітика: перехід статусу інциденту). Дві сторінки на різних портах `localhost` є одним site, але різними origin, тому `SameSite=Lax` і CORS цього не зупиняють (CORS обмежує лише читання відповіді). Ймовірність у навчальному стенді помірна: потрібен активний сеанс і відкрита чужа сторінка. CVSS не обчислювався.

## Першопричина
На маршрутах не було перевірки, що запит зроблено свідомою дією нашого клієнта: браузер сам додає cookie до змінювальних запитів, і сервер не міг відрізнити їх від запитів, ініційованих чужою сторінкою.

## Виправлення
`AddAntiforgery` (заголовок `X-SecureLab-CSRF`, cookie `SecureLab.Antiforgery`: HttpOnly, SameSite=Strict, Secure поза Development), маршрут `GET /api/csrf-token` (лише для автентифікованих), один `AntiforgeryFilter` на кожному змінювальному маршруті, клієнтський helper `Client/csrf.js` (токен береться перед першою змінювальною дією, тримається в пам'яті, скидається при login, logout, 400/401 і `pageshow`, запит після відмови не повторюється). Commit `7e6a20c`.

## Retest (після виправлення)
- reset, Morgan: статус до `New`; `triage` без токена → 400, статус `New`; після `GET /api/csrf-token` (разом із cookie) `triage` з `X-SecureLab-CSRF` → 200, статус `Triaged`.
- Повторний PoC з 4174: у Network `POST …/triage` → 400 Bad Request, handler не виконується.
- Порядок перевірок: повторний `triage` того самого інциденту з валідним токеном дає 409 Conflict (токен прийнято, відхилило бізнес-правило), без токена 400 (antiforgery спрацьовує раніше за бізнес-логіку).

## Positive regression
Легітимні дії клієнта працюють: login 204; створення в `auth-lab.html` («Створено: …»); `browser-lab.html` створити й прочитати (`POST: 201`, `GET: 200`); F5 і повторне створення (201); logout (`session-check: 401`); вхід іншого користувача (Morgan) і створення (201). Тести `Lab06HardeningTests.RegCsrf01_Triage_…`, `RegCsrf01_Perimeter_EveryMutationWithoutToken_Returns400`, `Anonymous_Mutation_Returns401_NotAntiforgery400`: pass.

## Залишковий ризик
`login` і `register` без токена (login CSRF): токен видається лише після входу. Токен доступний коду, що виконується на власному origin, тому antiforgery не замінює safe DOM (XSS лишається окремим класом ризику). Приймається в межах цієї лабораторної.

## Доказ
Команди й вивід: Рис. 8–12 звіту; тести `dotnet test … --configuration Release` (47 з 47). Пароль, cookie і значення токена в доказах не наводяться.