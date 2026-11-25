namespace CredProx.LiveTests;

/// <summary>
/// The bearer-shape test the shipped stand-in arms apply to the Authorization header
/// that arrives with a documented tool call: only a JWT-shaped bearer value latches the
/// collection's bearer witness (the live cells pin that witness false for their own
/// traffic — "the caller's bearer token never reaches the upstream"). The shape lives
/// here as a pure predicate, used by both fixtures' arms, so the offline precision cells
/// can pin both directions without driving the collection's sticky flag: class order
/// inside a collection must not decide which cell sees the witness set.
/// </summary>
internal static class StandInBearerWitness
{
    public static bool IsJwtShaped(string? authorization) =>
        authorization is not null
        && authorization.StartsWith("Bearer eyJ", StringComparison.Ordinal);
}
