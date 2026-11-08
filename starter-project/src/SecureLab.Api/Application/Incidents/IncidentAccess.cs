using System.Security.Claims;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// Які дії бувають з інцидентом.
public enum IncidentOperation
{
    Read,    // переглянути
    Update,  // змінити заголовок/опис
    Delete,  // видалити
    Triage   // привілейований перехід New -> Triaged
}

// ЄДИНЕ місце, де записано правила доступу (матриця з docs/access-matrix.md).
// Усі endpoints питають тут, а не вигадують власні умови.
// Вхід рішення: ХТО (user з cookie) + ЯКА ДІЯ + ЯКИЙ РЕСУРС (incident) + контекст (його статус).
public static class IncidentAccess
{
    // Id поточного користувача беремо ЛИШЕ з перевіреного principal (cookie), ніколи з тіла запиту.
    public static Guid? GetUserId(ClaimsPrincipal user)
    {
        var value = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(value, out var id) ? id : null;
    }

    public static bool IsAnalyst(ClaimsPrincipal user) => user.IsInRole(DbSeeder.AnalystRole);

    // Список: Analyst бачить усі інциденти, решта — лише власні.
    public static bool CanSeeAllIncidents(ClaimsPrincipal user) => IsAnalyst(user);

    // Внутрішні коментарі бачить лише Analyst.
    public static bool CanSeeInternalComments(ClaimsPrincipal user) => IsAnalyst(user);

    public static bool IsAllowed(ClaimsPrincipal user, Incident incident, IncidentOperation operation)
    {
        var userId = GetUserId(user);
        if (userId is null)
        {
            return false;
        }

        var isOwner = incident.OwnerUserId == userId.Value;
        var isAnalyst = IsAnalyst(user);

        return operation switch
        {
            IncidentOperation.Read => isOwner || isAnalyst,
            IncidentOperation.Update => isOwner,
            IncidentOperation.Delete => isOwner && incident.Status == IncidentStatus.New,
            IncidentOperation.Triage => isAnalyst,
            _ => false
        };
    }

    // Дочірній ресурс: спочатку право на батьківський інцидент, потім правило internal.
    public static bool CanReadComment(ClaimsPrincipal user, IncidentComment comment) =>
        IsAllowed(user, comment.Incident, IncidentOperation.Read)
        && (!comment.IsInternal || CanSeeInternalComments(user));
}