using CredProx.Abstractions;
using Microsoft.AspNetCore.Http;

namespace CredProx;

/// <summary>
/// The metering request-side leg (M50, ADR-0008): counts the request body bytes actually
/// handed upstream, as the last request feature (<see cref="Stage.Send"/>) so the wrapper
/// sees the body the forwarder will send — including anything an earlier feature rewrote.
/// The seam is the stream the forwarder pumps, in whichever form the content owns it: for
/// the content YARP itself binds (forwarder-owned; it hands out no read stream and its
/// reference must not be replaced — the forwarder's creation guard says configure
/// <c>HttpContext.Request</c> instead) the wrapper is installed on <c>context.Request.Body</c>,
/// the stream it serializes at send time, the same body the core's own measurement reads
/// and re-installs; content a leg owns hands out a stream normally and is wrapped through
/// the content with its headers copied. A short-circuited request never reaches the
/// forwarder, the counter is never read, and the record is scheduled by the response-side
/// feature — which never runs for a short circuit — so short-circuited requests never
/// count.
/// </summary>
internal sealed class CredProxMeteringRequestFeature : IRequestFeature
{
    /// <inheritdoc />
    public Stage Stage => Stage.Send;

    /// <inheritdoc />
    public async ValueTask ApplyAsync(HttpContext context, CancellationToken cancellationToken)
    {
        if (context.Features.Get<MeteringRequestState>() is not null)
        {
            return; // already wrapped: a re-run of the transform must not double-count
        }

        var state = context.Features.Get<CredProxRequestState>();
        if (state is null)
        {
            return; // not a CredProx-pipelined request (defensive: no metering, no error)
        }

        var content = state.ProxyRequest.Content;
        if (content is null)
        {
            context.Features.Set(new MeteringRequestState()); // bodyless request: zero request bytes
            return;
        }

        // The content YARP binds is forwarder-owned: it hands out no read stream by design
        // (its serialization pumps bytes straight through; ReadAsStreamAsync throws
        // NotImplementedException), and replacing its reference trips the forwarder's
        // request-creation guard — "configure HttpContext.Request instead". For that
        // content the stream pumped at send time is context.Request.Body, which core's own
        // body measurement also reads and re-installs (a leg that measured a body has
        // already swapped this to the exact bytes being sent), so the wrapper installs on
        // the body and the content reference stays the forwarder's. Content whose stream
        // hands out normally — a leg that owns and replaced it, or a non-forwarder host —
        // wraps through the content, headers copied as the core's scrubber replacement does.
        Stream original;
        var forwarderOwned = false;
        try
        {
            original = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (NotImplementedException)
        {
            original = context.Request.Body;
            forwarderOwned = true;
        }

        var counting = new CountingReadStream(original);
        if (forwarderOwned)
        {
            context.Request.Body = counting;
        }
        else
        {
            var replacement = new StreamContent(counting);
            foreach (var (name, values) in content.Headers)
            {
                replacement.Headers.TryAddWithoutValidation(name, values);
            }

            // The wrapper forwards every byte, so the copied content headers stay true.
            state.ProxyRequest.Content = replacement;
        }

        context.Features.Set(new MeteringRequestState { RequestBytes = counting });
    }
}
