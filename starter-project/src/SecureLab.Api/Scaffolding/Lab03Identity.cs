using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        // Обмеження частоти для /api/auth/login (добрий рівень). Значення читаються з
        // конфігурації на кожен запит, щоб ізольований тестовий host міг підмінити їх
        // через ConfigureAppConfiguration, не чіпаючи цю реєстрацію й не впливаючи на
        // спільний лічильник, яким користуються решта тестів.
        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("login", httpContext =>
            {
                var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
                var permitLimit = configuration.GetValue("RateLimiting:LoginPermitLimit", 50);
                var windowSeconds = configuration.GetValue("RateLimiting:LoginWindowSeconds", 30);

                
                var partitionKey = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = permitLimit,
                    Window = TimeSpan.FromSeconds(windowSeconds),
                    QueueLimit = 0
                });
            });
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.UseRateLimiter();

        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = new Dictionary<string, string[]>();

            // 1. Базові перевірки контракту: обов'язковість і довжина на надісланому значенні.
            if (string.IsNullOrWhiteSpace(input.UserName))
                errors["userName"] = ["Ім'я користувача обов'язкове."];
            else if (input.UserName.Length > 256)
                errors["userName"] = ["Ім'я користувача не довше за 256 символів."];

            if (string.IsNullOrWhiteSpace(input.Email))
                errors["email"] = ["Email обов'язковий."];
            else if (input.Email.Length > 256)
                errors["email"] = ["Email не довший за 256 символів."];

            // Identity власної довжини DisplayName не перевіряє — контракт задаємо самі.
            if (string.IsNullOrWhiteSpace(input.DisplayName))
                errors["displayName"] = ["Ім'я для відображення обов'язкове."];
            else if (input.DisplayName.Length > 120)
                errors["displayName"] = ["Ім'я для відображення не довше за 120 символів."];

            if (string.IsNullOrEmpty(input.Password))
                errors["password"] = ["Пароль обов'язковий."];

            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };

            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();

                // 2. Предметний конфлікт: ім'я користувача або email уже зайняті —
                //    запит синтаксично коректний, але суперечить наявному стану даних.
                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                {
                    return Results.Problem(
                        statusCode: StatusCodes.Status409Conflict,
                        title: "Обліковий запис із такими даними вже існує",
                        detail: "Ім'я користувача або email уже зареєстровано.");
                }

                // 3. Решта помилок Identity (формат, складність пароля) — 400 з ключем поля.
                var registrationErrors = new Dictionary<string, string[]>();
                foreach (var code in codes)
                {
                    var key = code switch
                    {
                        "InvalidUserName" => "userName",
                        "InvalidEmail" => "email",
                        _ when code.StartsWith("Password", StringComparison.Ordinal) => "password",
                        _ => "request"
                    };
                    registrationErrors.TryAdd(key, [DescribeIdentityError(code)]);
                }
                return Results.ValidationProblem(registrationErrors);
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            // 4. Response DTO: лише поля зовнішнього контракту, без password hash чи інших полів.
            var response = new RegisteredUserResponse(user.Id, user.UserName, user.DisplayName);
            return Results.Created("/api/me", response);
        });

        app.MapPost("/api/auth/login", async (
            LoginInput input,
            SignInManager<ApplicationUser> signIn,
            ILogger<Program> logger,
            HttpContext httpContext) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);

            // Подія автентифікації (добрий рівень): тип, ім'я користувача (ідентифікація,
            // не секрет), результат і traceId. Пароль, cookie, hash і тіло запиту сюди
            // не потрапляють.
            logger.LogInformation(
                "Authentication event {EventType}: user {UserName}, result {Result}, trace {TraceId}",
                "login", input.UserName, result.Succeeded ? "success" : "failure", httpContext.TraceIdentifier);

            // Єдина 401-відповідь для неіснуючого користувача й неправильного пароля —
            // захист від account enumeration (A-07).
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("login");

        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        });

        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new CurrentUserResponse(verifiedUserId, userName, role));
    }

    private static string DescribeIdentityError(string code) => code switch
    {
        "PasswordTooShort" => "Пароль має містити щонайменше 10 символів.",
        "PasswordRequiresDigit" => "Пароль має містити хоча б одну цифру.",
        "PasswordRequiresLower" => "Пароль має містити хоча б одну малу літеру.",
        "PasswordRequiresUpper" => "Пароль має містити хоча б одну велику літеру.",
        "PasswordRequiresNonAlphanumeric" => "Пароль має містити символ, що не є літерою чи цифрою.",
        "InvalidUserName" => "Ім'я користувача містить недозволені символи.",
        "InvalidEmail" => "Email має бути коректною адресою.",
        _ => "Дані реєстрації не відповідають вимогам."
    };
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegisteredUserResponse(Guid Id, string UserName, string DisplayName);
public sealed record CurrentUserResponse(Guid UserId, string UserName, string Role);
