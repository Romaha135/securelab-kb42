using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Security;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    private static readonly IReadOnlyDictionary<string, IncidentStatus> AllowedSummaryStatuses =
        new Dictionary<string, IncidentStatus>(StringComparer.OrdinalIgnoreCase)
        {
            ["New"] = IncidentStatus.New,
            ["Triaged"] = IncidentStatus.Triaged,
            ["InProgress"] = IncidentStatus.InProgress,
            ["Resolved"] = IncidentStatus.Resolved,
            ["Closed"] = IncidentStatus.Closed
        };

    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        // .RequireAuthorization() = без входу сервер відповідає 401.
        // Далі всередині кожного методу сервер ще питає: "а чи має ЦЕЙ користувач право на ЦЕЙ інцидент?"
        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem()
            .RequireAuthorization();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization()
            .AddEndpointFilter<AntiforgeryFilter>();

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization()
            .AddEndpointFilter<AntiforgeryFilter>();

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .RequireAuthorization()
            .AddEndpointFilter<AntiforgeryFilter>();

        // severity-summary та search — рівень "Відмінно" (A-11), тут не змінюємо.
        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        return endpoints;
    }

    // Політика проєкту: інцидент існує, але не твій -> 403. Інциденту немає -> 404.
    private static IResult NotFound(Guid id) => Results.Problem(
        title: "Інцидент не знайдено",
        detail: $"Інцидент '{id}' не існує.",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult Forbidden() => Results.Problem(
        title: "Доступ заборонено",
        detail: "У вас немає права виконати цю дію з цим інцидентом.",
        statusCode: StatusCodes.Status403Forbidden);

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var userId = IncidentAccess.GetUserId(httpContext.User);
        if (userId is null)
        {
            return Results.Unauthorized();
        }

        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        var seeAll = IncidentAccess.CanSeeAllIncidents(httpContext.User);
        return Results.Ok(await queries.GetListAsync(parsedStatus, userId.Value, seeAll, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindForAccessAsync(id, cancellationToken);
        if (incident is null)
        {
            return NotFound(id);
        }

        if (!IncidentAccess.IsAllowed(httpContext.User, incident, IncidentOperation.Read))
        {
            return Forbidden();
        }

        var includeInternal = IncidentAccess.CanSeeInternalComments(httpContext.User);
        var details = await queries.GetDetailsAsync(id, includeInternal, cancellationToken);
        return details is null ? NotFound(id) : Results.Ok(details);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        // Завантажуємо БЕЗ AsNoTracking(), інакше SaveChanges нічого не збереже.
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return NotFound(id);
        }

        // Спочатку право, потім усе інше. Жодних змін до цього рядка.
        if (!IncidentAccess.IsAllowed(httpContext.User, incident, IncidentOperation.Update))
        {
            return Forbidden();
        }

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Тема обов'язкова."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Тема не довша за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не довший за 4000 символів."];

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        // Змінюємо лише дозволені поля. Owner, Status, Severity клієнт задати не може.
        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return NotFound(id);
        }

        if (!IncidentAccess.IsAllowed(httpContext.User, incident, IncidentOperation.Delete))
        {
            return Forbidden();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // Привілейована дія: лише Analyst, лише New -> Triaged. Наступний статус задає СЕРВЕР.
    // У запиті немає тіла, тому клієнт нічого не може підмінити.
    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var userId = IncidentAccess.GetUserId(httpContext.User);
        if (userId is null)
        {
            return Results.Unauthorized();
        }

        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return NotFound(id);
        }

        if (!IncidentAccess.IsAllowed(httpContext.User, incident, IncidentOperation.Triage))
        {
            // Аудиторська подія: хто, що, над чим, результат, коли, і той самий traceId, що піде у відповідь.
            // Пароль, cookie та тіло запиту сюди не потрапляють.
            logger.LogWarning(
                "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
                + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
                userId.Value,
                "incident.triage",
                incident.Id,
                "denied",
                DateTimeOffset.UtcNow,
                Activity.Current?.Id ?? httpContext.TraceIdentifier);
            return Forbidden();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід неможливий",
                detail: "Передати на triage можна лише інцидент зі статусом New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        var now = DateTimeOffset.UtcNow;
        var oldStatus = incident.Status;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = userId.Value,
            OldStatus = oldStatus,
            NewStatus = IncidentStatus.Triaged,
            Note = "Первинну оцінку виконано (triage).",
            CreatedAtUtc = now
        });
        await dbContext.SaveChangesAsync(cancellationToken);

        // Аудит успішного переходу: той самий набір полів, що й для відмови вище.
        logger.LogInformation(
            "incident.status.changed subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} from={OldStatus} to={NewStatus} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            userId.Value,
            "incident.triage",
            incident.Id,
            "allowed",
            oldStatus,
            incident.Status,
            now,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);

        return Results.Ok(new { id = incident.Id, status = incident.Status.ToString() });
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? statusFilter = null;
        if (status is not null)
        {
            if (!AllowedSummaryStatuses.TryGetValue(status, out var allowedStatus))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            statusFilter = allowedStatus;
        }

        return Results.Ok(await queries.GetSeveritySummaryAsync(statusFilter, cancellationToken));
    }
}