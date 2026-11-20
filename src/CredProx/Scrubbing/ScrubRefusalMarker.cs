namespace CredProx;

/// <summary>
/// Set on the request's feature collection when the response scrubber refused an
/// uninspectable response (<c>CredProx:Scrubbing:FailClosed</c>). The error
/// normaliser checks for it so the refusal document — a CredProx problem shape —
/// is never re-normalised as if it were the vendor's own error body.
/// </summary>
internal sealed class ScrubRefusalMarker
{
    internal static readonly ScrubRefusalMarker Shared = new();

    private ScrubRefusalMarker()
    {
    }
}
