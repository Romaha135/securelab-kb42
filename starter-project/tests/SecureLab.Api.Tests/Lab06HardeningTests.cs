using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// Тести ЛР 6. Перед запуском: reset бази і змінна SeedUsers__Password (поза Git).
public sealed class Lab06HardeningTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.IncidentComments.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(row => row.Id == id).ExecuteDeleteAsync();
    }

    private static async Task<Guid> CreateIncidentAsync(HttpClient clientWithToken, string title)
    {
        using var response = await clientWithToken.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "Опис тестового інциденту для перевірки CSRF.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("id").GetGuid();
    }

    private static async Task<string> ReadStatusAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("status").GetString() ?? string.Empty;
    }

    private static async Task AssertAntiforgeryRejectionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("Antiforgery", body, StringComparison.Ordinal);
    }

    // REG-CSRF-01: triage без токена / з хибним токеном / з токеном іншого користувача -> 400,
    // статус ресурсу не змінився; з валідною парою токенів -> 200 і статус Triaged.
    [Fact]
    public async Task RegCsrf01_Triage_WithoutValidToken_IsRejected_AndStateUnchanged_ThenValidPairSucceeds()
    {
        var password = RequireSeedPassword();
        using var alice = await factory.LoginAsync("alice", password);
        var id = await CreateIncidentAsync(alice, $"CSRF-{Guid.NewGuid():N}");
        try
        {
            using var morgan = await factory.LoginWithoutTokenAsync("morgan", password);
            Assert.Equal("New", await ReadStatusAsync(morgan, id));

            // 1. Без токена.
            using (var noToken = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null))
            {
                await AssertAntiforgeryRejectionAsync(noToken);
            }
            Assert.Equal("New", await ReadStatusAsync(morgan, id));

            // 2. Хибний токен.
            using (var bad = new HttpRequestMessage(HttpMethod.Post, $"/api/incidents/{id}/triage"))
            {
                bad.Headers.Add(CookieClient.CsrfHeaderName, "invalid-token-value");
                using var badResponse = await morgan.SendAsync(bad);
                await AssertAntiforgeryRejectionAsync(badResponse);
            }
            Assert.Equal("New", await ReadStatusAsync(morgan, id));

            // 3. Токен іншого користувача (Alice) з cookie Morgan.
            var aliceToken = await alice.GetCsrfTokenAsync();
            using (var foreign = new HttpRequestMessage(HttpMethod.Post, $"/api/incidents/{id}/triage"))
            {
                foreign.Headers.Add(CookieClient.CsrfHeaderName, aliceToken);
                using var foreignResponse = await morgan.SendAsync(foreign);
                await AssertAntiforgeryRejectionAsync(foreignResponse);
            }
            Assert.Equal("New", await ReadStatusAsync(morgan, id));

            // 4. Валідна пара: токен Morgan + його cookie.
            var morganToken = await morgan.GetCsrfTokenAsync();
            using (var good = new HttpRequestMessage(HttpMethod.Post, $"/api/incidents/{id}/triage"))
            {
                good.Headers.Add(CookieClient.CsrfHeaderName, morganToken);
                using var goodResponse = await morgan.SendAsync(good);
                Assert.Equal(HttpStatusCode.OK, goodResponse.StatusCode);
            }
            Assert.Equal("Triaged", await ReadStatusAsync(morgan, id));
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Периметр: кожен cookie-мутаційний маршрут без токена -> 400 і стан не змінено.
    [Fact]
    public async Task RegCsrf01_Perimeter_EveryMutationWithoutToken_Returns400()
    {
        var password = RequireSeedPassword();
        using var aliceWithToken = await factory.LoginAsync("alice", password);
        var id = await CreateIncidentAsync(aliceWithToken, $"CSRF-PERIM-{Guid.NewGuid():N}");
        try
        {
            using var aliceCookieOnly = await factory.LoginWithoutTokenAsync("alice", password);

            using (var put = await aliceCookieOnly.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = "ЗМІНЕНО без токена",
                description = "Цей текст не повинен потрапити в базу."
            }))
            {
                await AssertAntiforgeryRejectionAsync(put);
            }

            using (var delete = await aliceCookieOnly.DeleteAsync($"/api/incidents/{id}"))
            {
                await AssertAntiforgeryRejectionAsync(delete);
            }

            using (var triage = await aliceCookieOnly.PostAsync($"/api/incidents/{id}/triage", content: null))
            {
                await AssertAntiforgeryRejectionAsync(triage);
            }

            using (var create = await aliceCookieOnly.PostAsJsonAsync("/api/incidents", new
            {
                title = $"CSRF-NEW-{Guid.NewGuid():N}",
                description = "Опис для перевірки створення без токена.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
            }))
            {
                await AssertAntiforgeryRejectionAsync(create);
            }

            using (var logout = await aliceCookieOnly.PostAsync("/api/auth/logout", content: null))
            {
                await AssertAntiforgeryRejectionAsync(logout);
            }

            // Сеанс після відмови logout лишився чинним, а інцидент - без змін.
            using var sessionCheck = await aliceCookieOnly.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.NoContent, sessionCheck.StatusCode);

            using var details = await aliceWithToken.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.OK, details.StatusCode);
            using var document = JsonDocument.Parse(await details.Content.ReadAsStringAsync());
            Assert.StartsWith("CSRF-PERIM-", document.RootElement.GetProperty("title").GetString(), StringComparison.Ordinal);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Анонім і далі отримує 401 (authorization працює раніше за antiforgery).
    [Fact]
    public async Task Anonymous_Mutation_Returns401_NotAntiforgery400()
    {
        using var anonymous = factory.CreateClient();
        using var response = await anonymous.PostAsync($"/api/incidents/{DbSeeder.AliceIncidentId}/triage", content: null);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // Rate limiting search: два partition (різні користувачі), quota, 429, відновлення.
    [Fact]
    public async Task Search_RateLimit_PartitionsAreIndependent_429_AndRecovers()
    {
        var password = RequireSeedPassword();
        using var isolated = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configurationBuilder) =>
            {
                configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RateLimiting:SearchPermitLimit"] = "3",
                    ["RateLimiting:SearchWindowSeconds"] = "2"
                });
            });
        });
        using var alice = await isolated.LoginAsync("alice", password);
        using var morgan = await isolated.LoginAsync("morgan", password);

        var aliceStatuses = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var response = await alice.GetAsync("/api/incidents/search?q=USB");
            aliceStatuses.Add(response.StatusCode);
        }

        Assert.Equal(
            new[] { HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests },
            aliceStatuses);

        // Інший partition (Morgan) не заблоковано квотою Alice.
        using (var morganResponse = await morgan.GetAsync("/api/incidents/search?q=USB"))
        {
            Assert.Equal(HttpStatusCode.OK, morganResponse.StatusCode);
        }

        // Відновлення після вікна.
        await Task.Delay(TimeSpan.FromSeconds(2.5));
        using var afterWindow = await alice.GetAsync("/api/incidents/search?q=USB");
        Assert.Equal(HttpStatusCode.OK, afterWindow.StatusCode);
    }

    // F-02: заголовки безпеки є й на контрольованій 500 (Production-подібний host, БД недосяжна).
    [Fact]
    public async Task UnexpectedError_Returns500_WithSecurityHeaders_AndNoInternals()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab",
                "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
                + "Password=unreachable-study-value;Include Error Detail=false");
        });
        using var client = production.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);

        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("traceId", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Npgsql", body, StringComparison.Ordinal);
        Assert.DoesNotContain("   at ", body, StringComparison.Ordinal);
    }
}
