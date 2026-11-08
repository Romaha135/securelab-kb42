using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentCommentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentCommentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetAsync)
            .WithName("GetIncidentComment")
            .WithTags("Incident comments")
            .Produces<IncidentCommentResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        return endpoints;
    }

    // Коментар читається "через" свого інциденту: якщо немає права на інцидент — немає права й на коментар.
    // Додатково internal-коментар бачить лише Analyst.
    private static async Task<IResult> GetAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var comment = await queries.FindCommentAsync(id, cancellationToken);
        if (comment is null)
        {
            return Results.Problem(
                title: "Коментар не знайдено",
                detail: $"Коментар '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound);
        }

        if (!IncidentAccess.CanReadComment(httpContext.User, comment))
        {
            return Results.Problem(
                title: "Доступ заборонено",
                detail: "У вас немає права переглядати цей коментар.",
                statusCode: StatusCodes.Status403Forbidden);
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc,
            comment.IsInternal));
    }
}