# Захист ЛР 4 (рівень «Добре»): Morgan-update щодо I1
 
Гілка: `lab/4-defense-morgan-update` (від `lab/4-authorization`, тег `v0.4.0` не переміщується).
 
## Паспорт відмов F/K/T (з `docs/access-matrix.md`)
 
| Позначка | Коли | Код |
|---|---|---|
| F | не увійшов (немає cookie) | **401** |
| K | ресурс існує, але дія не дозволена | **403** |
| T | такого id немає | **404** |
 
I1 = `20000000-0000-0000-0000-000000000001` — інцидент Alice (seed).
Початковий стан, зафіксований Alice: title `Підозрілий лист із вкладенням`, owner `Аліса Коваль`
(`owner_user_id = 10000000-0000-0000-0000-000000000001`), status `Triaged`.
 
## 1. Таблиця Read/Update 3×2 щодо I1
 
Код: `Application/Incidents/IncidentAccess.cs`, метод `IsAllowed`:
`Read => isOwner || isAnalyst`, `Update => isOwner`.
 
| Хто (роль) | isOwner | isAnalyst | **Read** (GET details) | **Update** (PUT) |
|---|---|---|---|---|
| Alice (Reporter, власник) | true | false | allow → 200 (гілка `isOwner`) | allow → 204 (гілка `isOwner`) |
| Bob (Reporter, не власник) | false | false | deny → 403 (K) | deny → 403 (K) |
| Morgan (Analyst, не власник) | false | true | allow → 200 (гілка `isAnalyst`) | **deny → 403 (K)** (`isAnalyst` в Update не враховується) |
 
**Де розходяться:** тільки рядок Morgan: Read = allow, Update = deny. Для Alice і Bob Read і Update збігаються.
Матриця й код тут збігаються: рядки «Деталі» та «Зміна вмісту» в `access-matrix.md` → `IsAllowed(Read)` / `IsAllowed(Update)`.
 
**Покриття власного A-04:** A-04 = Alice (чужий Reporter) змінює/видаляє інцидент Bob. Це випадок «Reporter, не власник»,
тобто рядок типу Bob, де Read і Update однаково deny. Рядок Morgan (Analyst, не власник) A-04 **не покриває**.
Крім того, A-04 перевіряє лише `title`, без owner/status.
 
## 2. Статичний мутант і вибір assertion
 
Мутант (Update дістає правило Read):
 
```csharp
IncidentOperation.Update => isOwner || isAnalyst,   // МУТАНТ
```
 
Письмова перевірка (ручне трасування, код не змінювався):
 
| Перевірка | Правильний код | Мутант |
|---|---|---|
| A-04: Alice PUT Bob | `isOwner=false` → 403 | `false \|\| false` = false → 403 → **A-04 зелений, мутант не видно** |
| WEB04: Morgan PUT I1 | `isOwner=false` → 403, I1 без змін | `false \|\| true` = true → валідація пройдена → `SaveChanges` → **204, title = WEB04-forbidden** |
 
Чому payload саме **валідний** (`title = WEB04-forbidden`, непорожній `description`): у `UpdateAsync` перевірка доступу
стоїть **перед** валідацією. На мутанті невалідний payload дав би 400 і не змінив стан, і тест,
який перевіряє лише «не 204» або «стан не змінився», лишився б зеленим. Валідний payload доводить запит на мутанті до запису.
 
Обрані assertion (тест `WEB04_Morgan_UpdateI1_Returns403_AndI1Unchanged`):
1. `put.StatusCode == 403` — **точний** код K, а не `!IsSuccessStatusCode` (бо 400 теж «не успіх»);
2. state assertion: `title/owner/status` до == після (HTTP очима Alice + рядок БД);
3. Morgan і після відмови читає I1 (200): відмова Update не зламала Read.
На мутанті тест падає вже на (1): 204 ≠ 403. Якщо хтось замінив би (1) на слабшу перевірку, тест усе одно впав би на (2): title змінився.
 
## 3. Три пов'язані спостереження (без reset)
 
| # | Що | Прогноз (до запуску) | Факт | Джерело |
|---|---|---|---|---|
| 1 | Morgan GET I1 | 200 | 200 | HTTP (тест) |
| 2 | Morgan PUT I1 `WEB04-forbidden` | 403 (K) | 403 | HTTP (тест) |
| 3 | Alice GET I1 після | 200, title/owner/status = початкові | без змін | HTTP (тест) + БД (тест) + SQL |
 
SQL-спостереження (БД напряму, до і після):
 
```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml exec postgres \
  psql -U securelab -d securelab -c "SELECT title, owner_user_id, status FROM incidents WHERE id = '20000000-0000-0000-0000-000000000001';"
```
 
SQL-переклад правила Update (як це виглядало б у запиті):
`UPDATE incidents SET title = @t WHERE id = @id AND owner_user_id = @currentUser` → для Morgan змінено 0 рядків.
Мутант відповідав би `... AND (owner_user_id = @currentUser OR @isAnalyst)` → змінено 1 рядок.
 
**Чому зелений Reporter-deny (A-04) не замінює цей контроль:** A-04 перевіряє лише суб'єкта без ролі Analyst. Для нього
`isOwner || isAnalyst` і `isOwner` дають однаковий результат, тому A-04 зелений і на правильному коді, і на мутанті.
Помилку «Update = правило Read» видно лише для суб'єкта, якому Read дозволено **не через власність**, тобто для Morgan.
 
**Якщо виявлено mutation:** не запускати `--reset-database`; зберегти вивід тесту, відповідь PUT і SQL-рядок;
потім адресно відновити лише I1 (не весь стан):
 
```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml exec postgres \
  psql -U securelab -d securelab -c "UPDATE incidents SET title = 'Підозрілий лист із вкладенням' WHERE id = '20000000-0000-0000-0000-000000000001';"
```
 
Після цього повторити `SELECT` і переконатися, що title, owner, status початкові.
 
## Як запустити
 
```powershell
$env:SeedUsers__Password = "<локальний пароль>"
dotnet test tests/SecureLab.Api.Tests --filter "FullyQualifiedName~Lab04DefenseTests" --logger "console;verbosity=detailed"
```
 