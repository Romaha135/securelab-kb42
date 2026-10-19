using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02ValidationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    // Пошук лишається анонімним endpoint ЛР 2 — для нього окремий клієнт без cookie.
    private readonly HttpClient _anonymousClient = factory.CreateClient();

    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // ЛР 3, етап 5: POST /api/incidents захищено, тому перевірки контракту ЛР 2
    // виконуються через автентифікований cookie client, а не анонімний.
    private Task<HttpClient> CreateAuthenticatedClientAsync() =>
        factory.LoginAsync("alice", RequireSeedPassword());

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    // T-02: порожній DTO одержує 400 з ключами всіх некоректних полів і без внутрішніх деталей.
    [Fact]
    public async Task Create_WithEmptyDto_Returns400WithAllFieldKeys()
    {
        using var client = await CreateAuthenticatedClientAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", new { });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("title", out _));
        Assert.True(errors.TryGetProperty("description", out _));
        Assert.True(errors.TryGetProperty("severity", out _));
        Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
    }

    // Невизначене числове значення enum (severity: "7") має відхилятись, а не ставати Low.
    [Fact]
    public async Task Create_WithUndefinedSeverityNumber_Returns400()
    {
        var body = new
        {
            title = "Severity probe",
            description = "Опис для перевірки некоректного значення severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var client = await CreateAuthenticatedClientAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("severity", out _));
    }

    // T-09 (добрий рівень): межа 39/40 символів для High/Critical.
    [Fact]
    public async Task Create_HighSeverityWithDescriptionBelow40_Returns400WithDescriptionKey()
    {
        var shortDescription = new string('x', 39);
        var body = new
        {
            title = $"T09-below-{Guid.NewGuid():N}",
            description = shortDescription,
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var client = await CreateAuthenticatedClientAsync();
        using var response = await client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("description", out _));
    }

    [Fact]
    public async Task Create_HighSeverityWithDescriptionAt40_Returns201()
    {
        var title = $"T09-at-{Guid.NewGuid():N}";
        var okDescription = new string('x', 40);
        var body = new
        {
            title,
            description = okDescription,
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var client = await CreateAuthenticatedClientAsync();
            using var response = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // T-03 (добрий рівень): предметний конфлікт для title, що вже активний.
    [Fact]
    public async Task Create_DuplicateActiveTitle_Returns409()
    {
        var title = $"T03-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Опис першого інциденту для перевірки конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var client = await CreateAuthenticatedClientAsync();
            using var first = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

            var json = await second.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            Assert.Equal("application/problem+json", second.Content.Headers.ContentType?.MediaType);
            Assert.False(document.RootElement.TryGetProperty("errors", out _));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // CP-01 (ЛР 2) / A-05 (ЛР 3): зайві server-managed поля в тілі запиту клієнт передати не може,
    // включно з ownerUserId — його ігнорує сам тип запиту (у ньому такого поля немає).
    [Fact]
    public async Task Create_WithOverpostedServerManagedFields_IgnoresClientValues()
    {
        var title = $"Overpost-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Опис для перевірки захисту від overposting.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            id = "11111111-1111-1111-1111-111111111111",
            status = "Closed",
            ownerUserId = "22222222-2222-2222-2222-222222222222",
            createdAtUtc = "2000-01-01T00:00:00Z"
        };

        try
        {
            using var client = await CreateAuthenticatedClientAsync();
            using var response = await client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            var json = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            Assert.NotEqual("11111111-1111-1111-1111-111111111111", root.GetProperty("id").GetString());
            Assert.Equal("New", root.GetProperty("status").GetString());
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // T-05: невідоме значення sortBy не доходить до SQL і дає 400 з ключем sortBy.
    // Пошук лишається анонімним, тому запит виконується без логіну.
    [Fact]
    public async Task Search_WithUnknownSortBy_Returns400WithSortByKey()
    {
        using var response = await _anonymousClient.GetAsync("/api/incidents/search?sortBy=price");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("errors").TryGetProperty("sortBy", out _));
    }

    // T-04 (позитивна регресія): легітимний апостроф не спричиняє 500 і знаходить очікуваний запис.
    [Fact]
    public async Task Search_WithLegitimateApostrophe_ReturnsExpectedRecordWithout500()
    {
        using var response = await _anonymousClient.GetAsync(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content
            .ReadFromJsonAsync<List<IncidentSearchResultResponse>>();
        Assert.NotNull(items);
        // Id задано у Lab02Seed.cs (номер 4) і не змінюється при reset.
        Assert.Contains(items, item => item.Id == Guid.Parse("20000000-0000-0000-0000-000000000004"));
    }

    // S-02 (ретест): контрольний SQLi-ввід після виправлення не розширює вибірку.
    [Fact]
    public async Task Search_WithSqlInjectionPayload_ReturnsEmptySet()
    {
        using var response = await _anonymousClient.GetAsync(
            "/api/incidents/search?q=" + Uri.EscapeDataString("zz-no-match' OR TRUE -- "));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content
            .ReadFromJsonAsync<List<IncidentSearchResultResponse>>();
        Assert.NotNull(items);
        Assert.Empty(items);
    }

    // Позитивний контроль поруч із S-02: пошук за звичайним словом усе ще працює.
    [Fact]
    public async Task Search_WithUsbQuery_ReturnsSingleSeededRecord()
    {
        using var response = await _anonymousClient.GetAsync("/api/incidents/search?q=USB");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content
            .ReadFromJsonAsync<List<IncidentSearchResultResponse>>();
        Assert.NotNull(items);
        Assert.Single(items);
        // Id задано у Lab02Seed.cs (номер 5) і не змінюється при reset.
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), items[0].Id);
    }
}
