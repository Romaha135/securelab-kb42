using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab03AuthenticationScenarioTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _anonymousClient = factory.CreateClient();

    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    // T-01: коректна реєстрація — 201, безпечна відповідь без password hash чи інших полів Identity.
    [Fact]
    public async Task Register_WithValidData_Returns201WithoutInternalFields()
    {
        var userName = $"student-{Guid.NewGuid():N}";
        using var response = await _anonymousClient.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Тестовий студент",
            password = "Str0ng-Study-Pass!"
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(userName, root.GetProperty("userName").GetString());
        Assert.Equal("Тестовий студент", root.GetProperty("displayName").GetString());
        Assert.False(root.TryGetProperty("passwordHash", out _));
        Assert.False(root.TryGetProperty("password", out _));
        Assert.DoesNotContain("PasswordHash", json, StringComparison.Ordinal);
    }

    // T-02: одна безпечна відмова для некоректного запиту (занадто короткий/слабкий пароль).
    [Fact]
    public async Task Register_WithWeakPassword_Returns400WithPasswordKey()
    {
        var userName = $"weakpass-{Guid.NewGuid():N}";
        using var response = await _anonymousClient.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Слабкий пароль",
            password = "abc"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("password", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    // T-02 (другий безпечний доказ): повторна реєстрація того самого userName — 409, не 500.
    [Fact]
    public async Task Register_WithDuplicateUserName_Returns409()
    {
        var userName = $"dup-{Guid.NewGuid():N}";
        var payload = new
        {
            userName,
            email = $"{userName}@example.test",
            displayName = "Дублікат",
            password = "Str0ng-Study-Pass!"
        };

        using var first = await _anonymousClient.PostAsJsonAsync("/api/auth/register", payload);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        using var second = await _anonymousClient.PostAsJsonAsync("/api/auth/register", new
        {
            userName,
            email = $"other-{Guid.NewGuid():N}@example.test",
            displayName = "Дублікат 2",
            password = "Str0ng-Study-Pass!"
        });

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        var json = await second.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    // A-01 (достатній, обов'язковий): анонімний запит до захищеного endpoint — 401, не HTML redirect.
    [Fact]
    public async Task Create_Anonymous_Returns401NotRedirect()
    {
        using var response = await _anonymousClient.PostAsJsonAsync("/api/incidents", new
        {
            title = "Anonymous probe",
            description = "Опис для перевірки анонімного запиту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // A-02 (достатній, обов'язковий): login → /api/me повертає верифікованого поточного користувача.
    [Fact]
    public async Task Login_ThenGetMe_ReturnsVerifiedCurrentUser()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());
        using var response = await client.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("userId").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.Equal("Reporter", root.GetProperty("role").GetString());
        Assert.False(root.TryGetProperty("passwordHash", out _));
    }

    // A-03 (добрий): підроблений заголовок X-Demo-UserId іншого користувача не змінює /api/me.
    [Fact]
    public async Task GetMe_WithForgedXDemoUserIdHeader_IdentityUnchanged()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("userId").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
    }

    // A-04 (добрий): автентифікований create без owner у DTO — owner береться з principal (Bob).
    [Fact]
    public async Task Create_AuthenticatedAsBobWithoutOwnerField_OwnerIsBob()
    {
        var title = $"A04-{Guid.NewGuid():N}";
        try
        {
            using var client = await factory.LoginAsync("bob", RequireSeedPassword());
            using var createResponse = await client.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Інцидент від Боба без явного owner у тілі запиту.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
            });
            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            using var createdDocument = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
            var id = createdDocument.RootElement.GetProperty("id").GetString();

            using var detailsResponse = await client.GetAsync($"/api/incidents/{id}");
            using var detailsDocument = JsonDocument.Parse(await detailsResponse.Content.ReadAsStringAsync());
            Assert.Equal("Боб Мельник", detailsDocument.RootElement.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-05 (достатній, обов'язковий): підроблений чужий ownerUserId у JSON не дає ескалації —
    // власник лишається Bob (принцип: до фіксу джерела owner цей тест упав би з owner = Alice).
    [Fact]
    public async Task Create_AuthenticatedAsBobWithForgedOwnerUserId_OwnerStaysBob()
    {
        var title = $"A05-{Guid.NewGuid():N}";
        try
        {
            using var client = await factory.LoginAsync("bob", RequireSeedPassword());
            using var createResponse = await client.PostAsJsonAsync("/api/incidents", new
            {
                title,
                description = "Інцидент від Боба з підробленим чужим ownerUserId.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                ownerUserId = DbSeeder.AliceId
            });
            Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
            using var createdDocument = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
            var id = createdDocument.RootElement.GetProperty("id").GetString();

            using var detailsResponse = await client.GetAsync($"/api/incidents/{id}");
            using var detailsDocument = JsonDocument.Parse(await detailsResponse.Content.ReadAsStringAsync());
            Assert.Equal("Боб Мельник", detailsDocument.RootElement.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-06 (добрий): logout, потім повторний захищений запит тим самим клієнтом — 401.
    [Fact]
    public async Task Logout_ThenProtectedRequest_Returns401()
    {
        using var client = await factory.LoginAsync("alice", RequireSeedPassword());
        using var beforeLogout = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.NoContent, beforeLogout.StatusCode);

        using var logoutResponse = await client.PostAsync("/api/auth/logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        using var afterLogout = await client.GetAsync("/api/auth/session-check");
        Assert.Equal(HttpStatusCode.Unauthorized, afterLogout.StatusCode);
    }

    // A-07 (добрий): невідомий користувач і неправильний пароль дають однаковий зовнішній результат
    // (захист від account enumeration). Порівнюються стабільні поля Problem Details, не traceId.
    [Fact]
    public async Task Login_UnknownUserAndWrongPassword_SameExternalResult()
    {
        using var unknownUserResponse = await _anonymousClient.PostAsJsonAsync("/api/auth/login", new
        {
            userName = $"nouser-{Guid.NewGuid():N}",
            password = "SomeRandomPassword123!"
        });

        using var wrongPasswordResponse = await _anonymousClient.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice",
            password = "DefinitelyWrongPassword123!"
        });

        Assert.Equal(unknownUserResponse.StatusCode, wrongPasswordResponse.StatusCode);
        Assert.Equal(
            unknownUserResponse.Content.Headers.ContentType?.MediaType,
            wrongPasswordResponse.Content.Headers.ContentType?.MediaType);

        // 401 від Results.Unauthorized() не має тіла — порівнюємо статус і Content-Type,
        // а не намагаємось розібрати порожнє тіло як Problem Details.
        Assert.Equal(HttpStatusCode.Unauthorized, unknownUserResponse.StatusCode);
    }

    // Rate limiting (добрий рівень): ізольований host із тимчасово звуженою політикою, щоб не
    // впливати на спільний лічильник, яким користуються решта тестів цього класу й файлу.
    [Fact]
    public async Task Login_AfterPermitLimit_Returns429AndRecoversAfterWindow()
    {
        using var isolatedFactory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configurationBuilder) =>
            {
                configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RateLimiting:LoginPermitLimit"] = "3",
                    ["RateLimiting:LoginWindowSeconds"] = "2"
                });
            });
        });
        using var client = isolatedFactory.CreateClient();
        var credentials = new { userName = "does-not-exist", password = "WrongPassword123!" };

        var statusCodes = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var response = await client.PostAsJsonAsync("/api/auth/login", credentials);
            statusCodes.Add(response.StatusCode);
        }

        Assert.Equal(
            new[]
            {
                HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized,
                HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests
            },
            statusCodes);

        await Task.Delay(TimeSpan.FromSeconds(2.5));

        using var afterWindow = await client.PostAsJsonAsync("/api/auth/login", credentials);
        Assert.Equal(HttpStatusCode.Unauthorized, afterWindow.StatusCode);
    }
}
