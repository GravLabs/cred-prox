namespace CredProx;

/// <summary>
/// Internal feature marker: this request authenticated with a credential that arrived in the
/// named inbound request header. Header hygiene reads it and strips that header from the
/// outbound request — on those paths the header IS the caller's credential and the upstream
/// must never see it; the vendor's own credential is attached afterwards as usual. An
/// authenticator whose credential is not a header value sets no marker, so those paths'
/// header behaviour is byte-for-byte unchanged. The header name arrives already validated:
/// the Abstractions factory rejects a malformed presented name where the result is made,
/// so a malformed one never reaches the request path and stripping is unconditional.
/// </summary>
internal sealed record PresentedCredential
{
    public PresentedCredential(string headerName)
    {
        ArgumentNullException.ThrowIfNull(headerName);
        HeaderName = headerName;
    }

    /// <summary>The inbound request header that carried the caller's credential.</summary>
    public string HeaderName { get; init; }
}
