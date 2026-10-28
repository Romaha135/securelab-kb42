namespace SecureLab.Api.Presentation.Contracts;

// Те, що клієнт має право надіслати для звичайної зміни інциденту.
// Тут ДОВІЛЬНО лише два поля. Немає ownerUserId, status, severity, role —
// тож клієнт навіть не може їх "передати" (а якщо надішле — сервер проігнорує).
public sealed record UpdateIncidentRequest(string? Title, string? Description);