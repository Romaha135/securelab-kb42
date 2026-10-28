using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

// ЛР 4: список і деталі тепер потребують входу, тому перші три тести
// використовують клієнта, що увійшов (login). Решта тестів — як були.
public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task GetList_ForAnalyst_ReturnsSeededIncidents()
    {
        // Morgan (Analyst) бачить усі інциденти.
        using var morgan = await factory.LoginAsync("morgan", RequireSeedPassword());
        var incidents = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var alice = await factory.LoginAsync("alice", RequireSeedPassword());
        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var alice = await factory.LoginAsync("alice", RequireSeedPassword());
        using var response = await alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var script = await _client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetSeveritySummary_ReturnsSeededGroupsInCriticalityOrder()
    {
        var summary = await _client.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");

        Assert.NotNull(summary);
        Assert.Equal(new[] { "High", "Medium", "Low" }, summary.Select(item => item.Severity));
        Assert.Equal(new[] { 1, 1, 3 }, summary.Select(item => item.Count));
    }

    [Fact]
    public async Task GetSeveritySummary_ForStatusWithoutIncidents_ReturnsEmptyArray()
    {
        var summary = await _client.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary?status=Resolved");

        Assert.NotNull(summary);
        Assert.Empty(summary);
    }

    [Fact]
    public async Task GetSeveritySummary_ForUnknownStatus_ReturnsValidationProblem400()
    {
        using var response = await _client.GetAsync("/api/incidents/severity-summary?status=Unknown");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }
}