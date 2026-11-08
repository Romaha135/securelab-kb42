using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// Тести ЛР 4 (рівень "Добре"). Перед запуском: reset бази і змінна SeedUsers__Password.
// Ідея кожного тесту: окремий клієнт на кожного користувача (Alice, Bob, Morgan, Admin),
// надсилаємо запит і перевіряємо ДВІ речі: код відповіді і те, що дані в базі не змінились.
public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid BobSearchIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private static readonly Guid MorganCommentOnBobId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");

    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private Task<HttpClient> LoginAsync(string userName) =>
        factory.LoginAsync(userName, RequireSeedPassword());

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    // Створює новий інцидент від імені client (він завжди має статус New) і повертає його id.
    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "Опис тестового інциденту для перевірки доступу.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var document = await ReadJsonAsync(response);
        return document.RootElement.GetProperty("id").GetGuid();
    }

    // Прибирання після тесту: видаляємо лише те, що створив сам тест.
    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.IncidentComments.Where(row => row.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(row => row.Id == id).ExecuteDeleteAsync();
    }

    // Читає деталі інциденту дозволеним клієнтом і повертає JSON (для порівняння "до/після").
    private static async Task<JsonDocument> GetDetailsJsonAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadJsonAsync(response);
    }

    // A-01: без входу — 401 (а не редирект на HTML-сторінку).
    [Fact]
    public async Task A01_Anonymous_ProtectedRequests_Return401()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var id = DbSeeder.AliceIncidentId;
        var requests = new (HttpMethod Method, string Url)[]
        {
            (HttpMethod.Get, "/api/incidents"),
            (HttpMethod.Get, $"/api/incidents/{id}"),
            (HttpMethod.Put, $"/api/incidents/{id}"),
            (HttpMethod.Delete, $"/api/incidents/{id}"),
            (HttpMethod.Post, $"/api/incidents/{id}/triage"),
            (HttpMethod.Get, $"/api/incident-comments/{InternalCommentId}")
        };

        foreach (var (method, url) in requests)
        {
            using var request = new HttpRequestMessage(method, url);
            if (method == HttpMethod.Put)
            {
                request.Content = JsonContent.Create(new { title = "x", description = "y" });
            }

            using var response = await anonymous.SendAsync(request);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        }
    }

    // A-02: Alice читає власний інцидент — дозволено.
    [Fact]
    public async Task A02_Owner_ReadsOwnIncident_Returns200()
    {
        using var alice = await LoginAsync("alice");
        using var details = await GetDetailsJsonAsync(alice, DbSeeder.AliceIncidentId);

        Assert.Equal("Підозрілий лист із вкладенням", details.RootElement.GetProperty("title").GetString());
    }

    // A-03: Alice читає інцидент Боба — заборонено (403) і дані Боба у відповіді відсутні.
    [Fact]
    public async Task A03_Reporter_ReadsForeignIncident_Returns403WithoutData()
    {
        using var alice = await LoginAsync("alice");
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain("Невідома спроба входу", body, StringComparison.Ordinal);
    }

    // A-03R: Morgan (Analyst) читає інцидент Alice — дозволено для аналізу.
    [Fact]
    public async Task A03R_Analyst_ReadsAliceIncident_Returns200()
    {
        using var morgan = await LoginAsync("morgan");
        using var details = await GetDetailsJsonAsync(morgan, DbSeeder.AliceIncidentId);

        Assert.Equal("Аліса Коваль", details.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    // Admin не отримує додаткових прав на чужий вміст (принцип мінімальних прав).
    [Fact]
    public async Task Admin_ReadsForeignIncident_Returns403()
    {
        using var admin = await LoginAsync("admin");
        using var response = await admin.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    // A-04: Alice не може змінити і видалити інцидент Боба; стан Боба не змінюється.
    [Fact]
    public async Task A04_Reporter_UpdateAndDeleteForeignIncident_Denied_StateUnchanged()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        using var before = await GetDetailsJsonAsync(morgan, DbSeeder.BobIncidentId);
        var titleBefore = before.RootElement.GetProperty("title").GetString();

        using var putResponse = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "ВЗЛОМ-Alice", description = "Alice змінює чужий інцидент." });
        Assert.Equal(HttpStatusCode.Forbidden, putResponse.StatusCode);

        using var deleteResponse = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.Forbidden, deleteResponse.StatusCode);

        using var after = await GetDetailsJsonAsync(morgan, DbSeeder.BobIncidentId);
        Assert.Equal(titleBefore, after.RootElement.GetProperty("title").GetString());
    }

    // A-05: список Alice не містить інцидентів Боба; список Morgan містить усіх.
    [Fact]
    public async Task A05_List_IsLimitedToAllowedSet()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        var aliceList = await alice.GetFromJsonAsync<List<SecureLab.Api.Presentation.Contracts.IncidentListItemResponse>>(
            "/api/incidents");
        var morganList = await morgan.GetFromJsonAsync<List<SecureLab.Api.Presentation.Contracts.IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(aliceList);
        Assert.NotNull(morganList);
        Assert.Contains(aliceList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(aliceList, item => item.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(aliceList, item => item.Id == BobSearchIncidentId);
        Assert.Contains(morganList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(morganList, item => item.Id == DbSeeder.BobIncidentId);
    }

    // A-06: Reporter не може виконати привілейований перехід; статус не змінюється.
    [Fact]
    public async Task A06_Reporter_Triage_Returns403_StatusUnchanged()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, $"A06-{Guid.NewGuid():N}");
        try
        {
            using var response = await alice.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

            using var after = await GetDetailsJsonAsync(alice, id);
            Assert.Equal("New", after.RootElement.GetProperty("status").GetString());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-07: Analyst виконує дозволений перехід New -> Triaged; повторний — 409.
    [Fact]
    public async Task A07_Analyst_Triage_Allowed_ThenSecondAttemptConflicts()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var id = await CreateIncidentAsync(alice, $"A07-{Guid.NewGuid():N}");
        try
        {
            using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);

            using var after = await GetDetailsJsonAsync(morgan, id);
            Assert.Equal("Triaged", after.RootElement.GetProperty("status").GetString());

            using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", null);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-08a: зайві поля (ownerUserId, status, severity, role) ігноруються; змінюється лише дозволений вміст.
    [Fact]
    public async Task A08a_Update_WithForgedFields_IgnoresProtectedFields()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, $"A08-{Guid.NewGuid():N}");
        var newTitle = $"A08-changed-{Guid.NewGuid():N}";
        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = newTitle,
                description = "Новий опис від власника.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                severity = "Critical",
                role = "Administrator"
            });
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

            using var after = await GetDetailsJsonAsync(alice, id);
            var root = after.RootElement;
            Assert.Equal(newTitle, root.GetProperty("title").GetString());
            Assert.Equal("New", root.GetProperty("status").GetString());
            Assert.Equal("Low", root.GetProperty("severity").GetString());
            Assert.Equal("Аліса Коваль", root.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // Власник може видалити свій інцидент у статусі New, після цього він зникає (404).
    [Fact]
    public async Task Owner_DeletesOwnNewIncident_Allowed()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, $"DEL-{Guid.NewGuid():N}");
        try
        {
            using var response = await alice.DeleteAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

            using var after = await alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.NotFound, after.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // A-12: дочірній ресурс (коментар) і internal comment.
    [Fact]
    public async Task A12_Comment_ForeignAndInternal_AreProtected()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        // Коментар Morgan до інциденту Bob: Alice читати не може навіть за прямим id.
        using var foreign = await alice.GetAsync($"/api/incident-comments/{MorganCommentOnBobId}");
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);

        // Internal-коментар до інциденту самої Alice: їй він теж недоступний.
        using var internalForAlice = await alice.GetAsync($"/api/incident-comments/{InternalCommentId}");
        Assert.Equal(HttpStatusCode.Forbidden, internalForAlice.StatusCode);

        // У деталях для Alice internal-коментаря немає.
        using var aliceDetails = await GetDetailsJsonAsync(alice, DbSeeder.AliceIncidentId);
        var aliceCommentIds = aliceDetails.RootElement.GetProperty("comments")
            .EnumerateArray().Select(item => item.GetProperty("id").GetGuid()).ToList();
        Assert.DoesNotContain(InternalCommentId, aliceCommentIds);

        // Для Morgan (Analyst) — і прямий доступ, і в деталях internal-коментар є.
        using var internalForMorgan = await morgan.GetAsync($"/api/incident-comments/{InternalCommentId}");
        Assert.Equal(HttpStatusCode.OK, internalForMorgan.StatusCode);

        using var morganDetails = await GetDetailsJsonAsync(morgan, DbSeeder.AliceIncidentId);
        var morganCommentIds = morganDetails.RootElement.GetProperty("comments")
            .EnumerateArray().Select(item => item.GetProperty("id").GetGuid()).ToList();
        Assert.Contains(InternalCommentId, morganCommentIds);
    }
}