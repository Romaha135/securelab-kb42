using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using Xunit.Abstractions;

namespace SecureLab.Api.Tests;

// ЗАХИСТ ЛР 4 (рівень "Добре"): Morgan (Analyst) читає I1, але НЕ може його змінити.
//
// I1 = інцидент Alice 20000000-0000-0000-0000-000000000001 (seed, status Triaged).
// Статичний мутант, який ловимо:   IncidentOperation.Update => isOwner || isAnalyst
// (тобто Update випадково отримав правило Read).
// A-04 (Alice -> Bob) на такому мутанті лишається ЗЕЛЕНИМ: Alice не owner і не Analyst,
// тому для неї Read і Update однакові (deny). Розходяться вони лише для Morgan.
//
public sealed class Lab04DefenseTests(SecureLabApiFactory factory, ITestOutputHelper output)
    : IClassFixture<SecureLabApiFactory>
{
    private static readonly Guid I1 = DbSeeder.AliceIncidentId;

    // Точний валідний payload: title з умови, description обов'язковий за валідацією UpdateAsync.
    // Валідний — щоб на мутанті запит дійшов до SaveChanges (а не зупинився на 400).
    private const string ForbiddenTitle = "WEB04-forbidden";
    private const string ForbiddenDescription = "WEB04 Morgan update attempt";

    private static string RequireSeedPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private Task<HttpClient> LoginAsync(string userName) =>
        factory.LoginAsync(userName, RequireSeedPassword());

    // Знімок того, що вимагає умова: title / owner / status.
    private sealed record I1State(string? Title, string? Owner, string? Status);

    // HTTP-спостереження: деталі I1 очима дозволеного клієнта.
    private static async Task<(HttpStatusCode Code, I1State? State)> ReadI1Async(HttpClient client)
    {
        using var response = await client.GetAsync($"/api/incidents/{I1}");
        if (response.StatusCode != HttpStatusCode.OK)
        {
            return (response.StatusCode, null);
        }

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        return (response.StatusCode, new I1State(
            root.GetProperty("title").GetString(),
            root.GetProperty("ownerDisplayName").GetString(),
            root.GetProperty("status").GetString()));
    }

    // БД-спостереження: той самий рядок напряму з таблиці incidents (owner як OwnerUserId).
    private async Task<I1State> ReadI1FromDbAsync()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var row = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == I1);
        return new I1State(row.Title, row.OwnerUserId.ToString(), row.Status.ToString());
    }

    // ---------------------------------------------------------------------
    // Крок 1. Таблиця Read/Update 3x2 щодо I1 — unit-рівень (без HTTP і БД).
    // Перевіряє саме гілки IncidentAccess.IsAllowed.
    // ---------------------------------------------------------------------
    [Theory]
    //          user      role         Read   Update
    [InlineData("alice",  "Reporter",  true,  true)]   // isOwner = true
    [InlineData("bob",    "Reporter",  false, false)]  // isOwner = false, isAnalyst = false
    [InlineData("morgan", "Analyst",   true,  false)]  // Read: isAnalyst; Update: лише isOwner -> РОЗХОДЖЕННЯ
    public void WEB04_Table_ReadUpdate_ForI1_MatchesMatrix(
        string user, string role, bool expectedRead, bool expectedUpdate)
    {
        var userId = user switch
        {
            "alice" => DbSeeder.AliceId,
            "bob" => DbSeeder.BobId,
            _ => DbSeeder.MorganId
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, userId.ToString()), new Claim(ClaimTypes.Role, role) },
            authenticationType: "unit"));
        var i1 = new Incident
        {
            Id = I1,
            OwnerUserId = DbSeeder.AliceId,
            Title = "I1",
            Description = "I1",
            Status = IncidentStatus.Triaged
        };

        Assert.Equal(expectedRead, IncidentAccess.IsAllowed(principal, i1, IncidentOperation.Read));
        Assert.Equal(expectedUpdate, IncidentAccess.IsAllowed(principal, i1, IncidentOperation.Update));
    }

    // ---------------------------------------------------------------------
    // Кроки 2-3. Morgan-read -> заборонений update -> незалежне післячитання Alice.
    // Прогноз (записаний ДО запуску): read 200, update 403, I1 до == після, Morgan read після 200.
    // ---------------------------------------------------------------------
    [Fact]
    public async Task WEB04_Morgan_UpdateI1_Returns403_AndI1Unchanged()
    {
        // Незалежні fixture: кожен користувач — свій клієнт зі своєю cookie.
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        // Стан "до" фіксує Alice (власник) + БД.
        var (aliceBeforeCode, before) = await ReadI1Async(alice);
        Assert.Equal(HttpStatusCode.OK, aliceBeforeCode);
        var dbBefore = await ReadI1FromDbAsync();

        // Доказ 1: Morgan читає I1 -> 200.
        var (morganReadCode, _) = await ReadI1Async(morgan);
        Assert.Equal(HttpStatusCode.OK, morganReadCode);

        // Доказ 2: Morgan змінює I1 валідним payload -> очікуємо рівно 403.
        using var put = await morgan.PutAsJsonAsync($"/api/incidents/{I1}",
            new { title = ForbiddenTitle, description = ForbiddenDescription });

        // Доказ 3: незалежне післячитання Alice + БД, без reset.
        var (aliceAfterCode, after) = await ReadI1Async(alice);
        var dbAfter = await ReadI1FromDbAsync();

        var evidence =
            $"PUT від Morgan = {(int)put.StatusCode}; HTTP до = {before}; HTTP після = {after}; "
            + $"БД до = {dbBefore}; БД після = {dbAfter}. "
            + "Якщо title = WEB04-forbidden — це mutation: НЕ робіть reset, збережіть цей вивід "
            + "і відновіть лише I1 (SQL UPDATE лише рядка I1, див. docs/defense-lab-04.md).";

        // Видно у виводі при: dotnet test --logger "console;verbosity=detailed"
        output.WriteLine($"ДОКАЗ 1: Morgan GET I1 = {(int)morganReadCode}");
        output.WriteLine($"ДОКАЗ 2: Morgan PUT I1 ({ForbiddenTitle}) = {(int)put.StatusCode}");
        output.WriteLine($"ДОКАЗ 3: Alice після = {after}; до = {before}");
        output.WriteLine($"БД до = {dbBefore}; БД після = {dbAfter}");

        // Головна assertion, що відрізняє мутант: точний 403 (мутант дає 204)...
        Assert.True(put.StatusCode == HttpStatusCode.Forbidden, evidence);
        // ...і state assertion: повний набір title/owner/status не змінився.
        Assert.Equal(HttpStatusCode.OK, aliceAfterCode);
        Assert.True(before == after, evidence);
        Assert.True(dbBefore == dbAfter, evidence);
        Assert.NotEqual(ForbiddenTitle, after!.Title);

        // Відмова Update НЕ забрала право Read: Morgan і далі бачить I1.
        var (morganReadAfterCode, _) = await ReadI1Async(morgan);
        Assert.Equal(HttpStatusCode.OK, morganReadAfterCode);
    }
}