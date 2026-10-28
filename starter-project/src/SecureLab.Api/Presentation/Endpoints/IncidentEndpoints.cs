using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

// УВАГА: це навмисно ВРАЗЛИВА версія для локального експерименту (ЛР 4, крок 4).
// Вхід (login) вимагається, але ПРАВО на конкретний інцидент НЕ перевіряється.
// Це і є IDOR/BOLA. Не використовуйте поза локальним стендом.
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

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem()
            .RequireAuthorization();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        // ВРАЗЛИВО: будь-який користувач, що увійшов, змінює будь-який інцидент за id.
        group.MapPut("/{id:guid}", UpdateVulnerableAsync)
            .WithName("UpdateIncident")
            .RequireAuthorization();

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
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

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    // ВРАЗЛИВО: шукає лише за id, не питає "чий це інцидент".
    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    // ВРАЗЛИВО: власник не перевіряється.
    private static async Task<IResult> UpdateVulnerableAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
        }

        if (!string.IsNullOrWhiteSpace(request.Title))
        {
            incident.Title = request.Title.Trim();
        }

        if (!string.IsNullOrWhiteSpace(request.Description))
        {
            incident.Description = request.Description.Trim();
        }

        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
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