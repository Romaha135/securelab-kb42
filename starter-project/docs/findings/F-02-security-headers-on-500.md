# F-02. Заголовки безпеки зникають на відповіді 500

**Статус:** Fixed
**Актив:** передбачувані заголовки браузерної безпеки на всіх класах відповідей
**Компонент:** порядок middleware у `Program.cs` (headers vs `UseExceptionHandler`)
**Пріоритет:** P3

## Передумови і межі огляду
Стан до виправлення: v0.5.0 (`bd636b1`); виправлення в H1 `7e6a20c`. Профіль Production-like (`--no-launch-profile -c Release`, `ASPNETCORE_ENVIRONMENT=Production`, підтверджено рядком `Hosting environment: Production`), недосяжний порт БД 54399. Профіль лише HTTP.

## Відтворення (до виправлення)
1. Production-like запуск зі штучно недосяжною БД (порт 54399).
2. Один `POST /api/auth/login` з вигаданим паролем.
3. `curl.exe -i`: відповідь 500 `application/problem+json`, `traceId` `00-ef38e78c…`; заголовків `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy` у відповіді немає (на 200, 400, 404 вони були). Запис `ExceptionHandlerMiddleware[1]` у журналі має той самий TraceId.

## Вплив і ймовірність
**Статус перевірки:** спостережено локально.
Помилкова відповідь не мала захисних заголовків, тобто послаблювався додатковий шар захисту (defense in depth) саме на помилковому шляху. Прямої експлуатації не виявлено; ймовірність низька (потрібна неочікувана помилка сервера). CVSS не обчислювався.

## Першопричина
Middleware заголовків стояв у `Program.cs` після `UseExceptionHandler`; обробник винятку формує нову відповідь і очищає попередню, тому заголовки, поставлені раніше по конвеєру, на помилковому шляху не потрапляли у відповідь.

## Виправлення
Middleware перенесено перед `UseExceptionHandler`, заголовки встановлюються в `Response.OnStarting`, тому діють і на помилковому шляху. Виняток для `/scalar` у Development збережено. Commit `7e6a20c`.

## Retest (після виправлення)
Той самий сценарій у Production-like: `500`, `application/problem+json`, `traceId` `00-24633bce…`, тепер є `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` і `Content-Security-Policy`; значення взято з реального запиту. Тіло без stack trace, SQL, шляхів і connection string. Запис `ExceptionHandlerMiddleware[1]` має той самий TraceId, що й відповідь.

## Positive regression
Заголовки п'яти класів відповідей без змін на 200, 400, 404 (статична сторінка, успішний API, validation, 404); клієнт працює під CSP (у Console на `/`, `/browser-lab.html`, `/auth-lab.html` порушень немає); `/scalar/v1` у Development без CSP, як і раніше. Тест `Lab06HardeningTests.UnexpectedError_Returns500_WithSecurityHeaders_AndNoInternals`: pass.

## Залишковий ризик
Лише навчальний HTTP-профіль: TLS, HSTS і розгортання не перевірялись. Заголовки не замінюють safe DOM і контроль доступу.

## Доказ
Таблиці 4 і 7 звіту (до/після), Рис. 4, 5 і 13; тести `dotnet test … --configuration Release` (47 з 47). Пароль, cookie і значення токена в доказах не наводяться.