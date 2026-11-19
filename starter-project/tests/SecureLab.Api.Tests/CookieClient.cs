using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    // Той самий рядок, що в CsrfDefaults.HeaderName (API) і Client/csrf.js.
    public const string CsrfHeaderName = "X-SecureLab-CSRF";

    // Клієнт із cookie-сеансом, але БЕЗ antiforgery-токена: для негативних CSRF-тестів.
    // Параметр - WebApplicationFactory<Program>, щоб працювали й похідні factory (WithWebHostBuilder).
    public static async Task<HttpClient> LoginWithoutTokenAsync(
        this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        return client;
    }

    // Звичайний клієнт: після входу тим самим клієнтом одержує токен і додає header до всіх запитів.
    public static async Task<HttpClient> LoginAsync(
        this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = await factory.LoginWithoutTokenAsync(userName, password);
        try
        {
            var token = await client.GetCsrfTokenAsync();
            client.DefaultRequestHeaders.Add(CsrfHeaderName, token);
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public static async Task<string> GetCsrfTokenAsync(this HttpClient client)
    {
        using var response = await client.GetAsync("/api/csrf-token");
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("token").GetString()
            ?? throw new InvalidOperationException("Empty antiforgery token.");
    }
}
