namespace CredProx;

/// <summary>
/// Internal feature marker: this request's caller authenticated with a caller TOKEN
/// rather than an API key. Header hygiene reads it and strips the caller's
/// <c>Authorization</c> header from the outbound request — on the token path that
/// header IS the credential and the upstream must never see it; the vendor's own
/// credential is attached afterwards as usual. The key path never sets this marker,
/// so key-path header behaviour is byte-for-byte unchanged.
/// </summary>
internal sealed record CallerTokenRequestMarker;
