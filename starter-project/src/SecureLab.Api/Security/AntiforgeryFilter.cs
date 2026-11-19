using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Security;

// Усе, що стосується CSRF-захисту, в одному місці:
// 1) реєстрація сервісу antiforgery, 2) маршрут видачі токена, 3) фільтр перевірки.
public static class CsrfDefaults
{
    // Назва header, у якому клієнт повертає request token. Той самий рядок у Client/csrf.js.
    public const string HeaderName = "X-SecureLab-CSRF";
}

public static class AntiforgeryRegistration
{
    public static IServiceCollection AddSecureLabAntiforgery(
        this IServiceCollection services, IHostEnvironment environment)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = CsrfDefaults.HeaderName;
            options.Cookie.Name = "SecureLab.Antiforgery";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            // Так само, як для cookie сеансу в Lab03Identity: на HTTPS завжди Secure.
            options.Cookie.SecurePolicy = environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
        });
        return services;
    }

    // Видача токена: cookie-частина йде в Set-Cookie, request token - у JSON.
    // Лише для користувача, що ввійшов: токен прив'язується до його identity.
    public static IEndpointRouteBuilder MapCsrfTokenEndpoint(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/csrf-token", (IAntiforgery antiforgery, HttpContext httpContext) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            return Results.Ok(new CsrfTokenResponse(tokens.RequestToken ?? string.Empty));
        })
        .WithName("GetCsrfToken")
        .RequireAuthorization();

        return endpoints;
    }
}

public sealed record CsrfTokenResponse(string Token);

// Один клас перевірки на кожному cookie-authenticated змінювальному маршруті.
// Authorization middleware працює раніше: анонім отримує 401, а не 400.
public sealed class AntiforgeryFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            // Ранній return: handler не виконується, стан ресурсу не змінюється.
            return Results.Problem(
                title: "Antiforgery-токен відсутній або недійсний.",
                detail: "Змінювальний запит має містити токен безпеки з /api/csrf-token.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}
