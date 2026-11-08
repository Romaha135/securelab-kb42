using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    // Список. Якщо seeAll = false (Reporter), у запит додається умова "лише мої".
    // Тобто чужі рядки навіть не завантажуються з бази.
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid currentUserId,
        bool seeAll,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents.AsNoTracking();
        if (!seeAll)
        {
            query = query.Where(incident => incident.OwnerUserId == currentUserId);
        }

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    // Завантажує сам інцидент (з OwnerUserId). Назовні цей об'єкт НЕ віддається —
    // він потрібен лише серверу, щоб ухвалити рішення "можна / не можна".
    public Task<Incident?> FindForAccessAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.Incidents
            .AsNoTracking()
            .SingleOrDefaultAsync(incident => incident.Id == id, cancellationToken);

    // Коментар разом із батьківським інцидентом (потрібен для перевірки права).
    public Task<IncidentComment?> FindCommentAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.IncidentComments
            .AsNoTracking()
            .Include(comment => comment.Incident)
            .Include(comment => comment.Author)
            .SingleOrDefaultAsync(comment => comment.Id == id, cancellationToken);

    // Деталі. includeInternal = true лише для Analyst; для Reporter внутрішні коментарі відсікаються.
    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        bool includeInternal,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternal || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc,
                        comment.IsInternal))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentStatus? status,
        CancellationToken cancellationToken)
    {
        var query = dbContext.Incidents.AsNoTracking();
        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        var groups = await query
            .GroupBy(incident => incident.Severity)
            .Select(entry => new { Severity = entry.Key, Count = entry.Count() })
            .ToListAsync(cancellationToken);

        // Severity зберігається як текст, тому порядок задаємо після матеріалізації:
        // значення enum зростає від Low до Critical, отже спадання дає порядок критичності.
        var result = groups
            .OrderByDescending(entry => entry.Severity)
            .Select(entry => new IncidentSeveritySummaryResponse(entry.Severity.ToString(), entry.Count))
            .ToList();

        logger.LogInformation(
            "Built severity summary for status filter {Status}: {GroupCount} groups",
            status,
            result.Count);

        return result;
    }
}