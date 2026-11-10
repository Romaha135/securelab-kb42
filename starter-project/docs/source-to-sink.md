# Власна карта source-to-sink

Поле: Incident.Description. Стан/commit: заповніть. Вхід/Guid запису: заповніть.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | Client/browser-lab.html, форма #edit, textarea name="description" | текст, який вводить користувач | контрольоване користувачем. Доказ: [заповни] |
| Request | Client/browser-lab.js, обробник submit → fetch POST /api/incidents | JSON-поле description | контрольоване користувачем. Доказ: Network → Payload [заповни] |
| Validation/mapping | Scaffolding/Lab02Endpoints.cs, create-обробник; Trim() | обов'язкове, ≤ 4000 символів; символи < і > не відхиляються | validation не робить текст безпечним для HTML. Доказ: [заповни] |
| Storage | Incident.Description, PostgreSQL | те саме значення без змін | збережене значення користувача. Доказ: [DB/API evidence] |
| Response | Application/Incidents/IncidentQueries.cs GetDetailsAsync → IncidentDetailsResponse.Description | JSON-поле description у GET /api/incidents/{id} | недовірене для відображення. Доказ: Network → Response [заповни] |
| Client transform | Client/browser-lab.js, load() | current.description | без перетворень. Доказ: [заповни] |
| Sink/context | Client/browser-lab.js, load(): `#description`.innerHTML = current.description (до fix) | HTML-контекст | небезпечний: браузер розбирає рядок як HTML. Після fix: renderText → createTextNode (текстовий контекст). Доказ: Elements до/після [заповни] |

Інвентаризація: файл/функція → категорія даних → контекст → обґрунтоване рішення. Для «Добре / Відмінно» додайте повний другий потік IncidentComment.Text за тією самою таблицею. Для «Відмінно» додайте результат поглибленої перевірки comments/повторного render. Рівні накопичувальні; основний Description потрібний для всіх.
