namespace SecureLab.Api.Presentation.Contracts;

public sealed record IncidentListItemResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);

public sealed record IncidentDetailsResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc,
    string OwnerDisplayName,
    IReadOnlyList<IncidentCommentResponse> Comments);

// Додано поле IsInternal (останнє), щоб Analyst бачив, що коментар внутрішній.
// Для Reporter внутрішні коментарі в список взагалі не потрапляють.
public sealed record IncidentCommentResponse(
    Guid Id,
    string AuthorDisplayName,
    string Text,
    DateTimeOffset CreatedAtUtc,
    bool IsInternal);

public sealed record IncidentSeveritySummaryResponse(
    string Severity,
    int Count);