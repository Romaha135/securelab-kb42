# Власна карта source-to-sink

Поле: Incident.Description (потік 1) і IncidentComment.Text (потік 2). Стан/commit: vulnerable 8c5bcda, seed 65f8d2c, виправлення XSS (C1) e122acc, CORS (C2) 9e45363, fixed [hash після кроку 6.4]. Вхід/Guid запису: alice, PoC-запис 2480eca0-28df-4013-806a-0340a67eeb19 (після reset видалений); коментар 30000000-0000-0000-0000-000000000005 в інциденті 20000000-0000-0000-0000-000000000001.

## Потік 1. Incident.Description

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Client/browser-lab.html, форма #edit, textarea name="description" | текст, який вводить користувач | контрольоване користувачем. Доказ: Elements: <textarea name="description"> у формі #edit; текст вводить користувач |
| Request | Client/browser-lab.js, обробник submit → fetch POST /api/incidents | JSON-поле description | контрольоване користувачем. Доказ: Network → POST incidents → Payload: description = marker (Рис. 7) |
| Validation/mapping | Scaffolding/Lab02Endpoints.cs, create-обробник; Trim() | обов'язкове, ≤ 4000 символів; символи < і > не відхиляються | validation не робить текст безпечним для HTML. Доказ: код перевіряє довжину й Trim; < і > не відхиляються, marker збережено без змін (desc-before.json) |
| Storage | Incident.Description, PostgreSQL | те саме значення без змін | збережене значення користувача. Доказ: desc-before.json: description = marker без змін |
| Response | Application/Incidents/IncidentQueries.cs GetDetailsAsync → IncidentDetailsResponse.Description | JSON-поле description у GET /api/incidents/{id} | недовірене для відображення. Доказ: Network → GET /api/incidents/{id} → Response і desc-before.json: той самий marker |
| Client transform | Client/browser-lab.js, load() | current.description | без перетворень. Доказ: browser-lab.js, рядок 10: current.description передається далі без перетворень |
| Sink/context | Client/browser-lab.js, load(): #description | HTML-контекст до fix; текстовий контекст після fix | До fix: innerHTML = current.description (браузер розбирає рядок як HTML), небезпечно. Доказ: browser-lab.js, рядок 10; Elements: <img src="x" onerror=…> у #description (Рис. 8). Після fix (commit e122acc): renderText(#description, current.description) → replaceChildren + createTextNode; Elements: один текстовий вузол, Console null (Рис. 13) |

## Потік 2. IncidentComment.Text (Добре / Відмінно)

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Data/DbSeeder.cs, SeedAsync, Lab05Marker (у продукті — будь-який автор коментаря) | Text коментаря …0005 | збережене значення користувача. Доказ: Data/DbSeeder.cs, commit 65f8d2c: додано comment-5 з marker |
| Request | GET /api/incidents/{id} (endpoint створення коментаря в API відсутній, коментар додано seed-ом) | не застосовується | не застосовується |
| Validation/mapping | немає окремої (endpoint створення коментаря відсутній) | не застосовується | не застосовується |
| Storage | IncidentComment.Text, PostgreSQL | marker без змін | збережене значення користувача. Доказ: у відповіді API (Network → Response) comments[].text дорівнює marker, без змін |
| Response | IncidentCommentResponse.Text | JSON comments[].text | недовірене для відображення. Доказ: Network → GET /api/incidents/20000000-0000-0000-0000-000000000001 → Response: comments[].text = marker |
| Client transform | Client/browser-lab.js, load(): цикл по current.comments | comment.text | без перетворень. Доказ: browser-lab.js, рядок 14: comment.text передається в sink без перетворень |
| Sink/context | Client/browser-lab.js, load(): paragraph (елемент в #comments) | HTML-контекст до fix; текстовий контекст після fix | До fix: paragraph.innerHTML = comment.text, небезпечно. Доказ: Elements: <img src="x" onerror=…> у #comments, Console 'executed' (Рис. 11). Після fix (commit e122acc): renderText(paragraph, comment.text); Elements: текстовий вузол у #comments; Console null у вікнах Alice і Morgan (Рис. 15) |

## Інвентаризація sinks (власний код у Client/)

| Файл / функція | Категорія даних | Контекст | Рішення |
|---|---|---|---|
| browser-lab.js, load(), #title | збережене значення користувача | текстовий вузол (textContent) | безпечно, не змінювалось |
| browser-lab.js, load(), #description | збережене значення користувача | HTML (innerHTML) | замінено на renderText |
| browser-lab.js, load(), comment.text | збережене значення користувача | HTML (innerHTML) | замінено на renderText |
| browser-lab.js, #status | server-generated (код статусу) | textContent | безпечно |
| app.js, createTextElement | дані API | textContent | безпечно (еталонний helper) |
| auth-lab.js, auth-lab.html | дані API та відповіді сервера | текст (за коментарем у коді, рядок 85, через textContent); innerHTML пошуком не знайдено | безпечно, змін не потребує |