using CredProx;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace CredProx.Tests;

/// <summary>
/// M31 mutation triage (Pipeline): the clone's typed-options re-key is the mechanism
/// the per-request stashes ride on; the decoding classifier's empty out-value and the
/// two degenerate media-type edges were the surviving judgement calls.
/// </summary>
public sealed class PipelineSurvivorM31bTests
{
    [Fact]
    public void Clone_TypedStateStash_RoundTripsAsItsRuntimeType()
    {
        // The retry clone re-keys Options with the value's runtime type; a typed
        // TryGetValue on the clone must still find the stash (the response dispatcher
        // resolves exactly this key).
        var state = new CredProxRequestState(
            new DefaultHttpContext(), new HttpRequestMessage(HttpMethod.Get, "http://upstream/api"));
        var request = new HttpRequestMessage(HttpMethod.Get, "https://vendor.example/api");
        request.Options.Set(CredProxRequestOptions.RequestState, state);

        var clone = ProxyRequestCloner.Clone(request, body: null);

        Assert.True(clone.Options.TryGetValue(CredProxRequestOptions.RequestState, out var restored));
        Assert.Same(state, restored);
    }

    [Fact]
    public void ResolveDecoding_NoContentEncoding_ReportsEmptyEncoding()
    {
        var decoding = ResponseBodies.ResolveDecoding(new StringContent("x"), out var decoder, out var encoding);

        Assert.Equal("UsableIdentity", decoding.ToString());
        Assert.Null(decoder);
        Assert.Equal(string.Empty, encoding); // callers log this verbatim — it must stay empty
    }

}
