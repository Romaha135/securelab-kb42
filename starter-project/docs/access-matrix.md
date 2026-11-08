# Матриця доступу SecureLab (ЛР 4, рівень «Добре»)

Як читати: «власник» — користувач, чий id записано в `OwnerUserId` інциденту. Роль і id користувача
сервер бере лише з cookie після входу, ніколи з тіла запиту.

**Політика відмов (одна для всього проєкту):**
- Не увійшов у систему → **401**.
- Інцидент (або коментар) існує, але ця дія вам не дозволена → **403**.
- Такого id немає в базі → **404**.

| Дія | Маршрут | Анонім | Reporter | Analyst | Administrator | Власник має значення? | Статус відмови | Де в коді |
|---|---|---|---|---|---|---|---|---|
| Список | `GET /api/incidents` | 401 | лише власні | усі | лише власні | Так (для Reporter/Admin) | — (чужі просто не потрапляють у список) | `IncidentQueries.GetListAsync` (умова `OwnerUserId == userId`) |
| Деталі | `GET /api/incidents/{id}` | 401 | власник — allow; інший — deny | allow (для аналізу) | deny, якщо не власник | Так | 403 | `IncidentAccess.IsAllowed(Read)` |
| Створення | `POST /api/incidents` | 401 | allow | allow | allow | Власника призначає сервер | — | `Lab02Endpoints` (з ЛР 3) |
| Зміна вмісту (title, description) | `PUT /api/incidents/{id}` | 401 | власник — allow; інший — deny | deny | deny, якщо не власник | Так | 403 | `IncidentAccess.IsAllowed(Update)` |
| Видалення | `DELETE /api/incidents/{id}` | 401 | власник і лише коли status = New | deny | deny, якщо не власник | Так | 403 | `IncidentAccess.IsAllowed(Delete)` |
| Triage (New → Triaged) | `POST /api/incidents/{id}/triage` | 401 | deny (навіть власнику) | allow лише коли status = New (інакше 409) | deny | Ні | 403 + запис аудиту | `IncidentAccess.IsAllowed(Triage)` + перевірка статусу |
| Зміна severity / status напряму | — | — | deny | лише через triage | deny | — | — | у `UpdateIncidentRequest` таких полів немає |
| Коментар за id | `GET /api/incident-comments/{id}` | 401 | лише якщо є право на його інцидент і коментар не internal | allow (після перевірки інциденту) | як Reporter | Через батьківський інцидент | 403 | `IncidentAccess.CanReadComment` |
| Internal-коментарі в деталях | у відповіді `GET /api/incidents/{id}` | — | не показуються | показуються | не показуються | Ні | — | параметр `includeInternal` |
| Пошук `GET /api/incidents/search` | — | не змінювалось | не виконувалось — рівень «Відмінно» | | | | | |
| Підсумок `GET /api/incidents/severity-summary` | — | не змінювалось | не виконувалось — рівень «Відмінно» | | | | | |

**Administrator:** окремих прав на чужі інциденти не має (принцип мінімальних прав). Адміністративні
дії предметною областю не опубліковано, тому для інцидентів він поводиться як звичайний користувач.

**Export / audit-перегляд:** не застосовується (такого функціоналу в проєкті немає).
