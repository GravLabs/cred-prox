# ADR-0008: Usage metering (M50) lives in CredProx.Operations on the existing seams

Status: Accepted (2026-11-23, at the M50 merge after an independent review and a passing live metered call; maintainer design rule 2026-11-22: "make sure it is integrated cleanly minimal core changes, as much plugins behaviour as possible").
Date: 2026-11-22

## Context

M50 (plan §7) adds per-caller/vendor usage metrics: a request counter, request/response byte
counts tagged by caller id, credential/vendor name, route and status class, plus opt-in LLM
token counts read from the provider's own usage report (Anthropic non-streaming `usage` and
streaming `message_start`/`message_delta`). Constraints from the plan and the row: tags are
names only (never a key, token, path parameter), tag cardinality is bounded by configuration
and not by traffic, reading usage must not buffer a streamed response or change what the
caller receives, and metering unregistered must mean zero behaviour change in core.

ADR-0005 defines the add-on rule ("register only through public seams, the same ones a third
party would use"; a needed `InternalsVisibleTo` means the seam is missing), ADR-0006 the
replace/extend rules, ADR-0007 the one-entry shape. This ADR records where metering goes and
what, if anything, core must change.

## Decision

**Placement.** Metering ships inside `CredProx.Operations`, armed by a `CredProx:Metering`
section through `.AddOperations()` like the throttle, resilience and health legs, and emits on
the existing `"CredProx"` meter (`OperationsDiagnostics`, name+version `CredProx`/`0.1.0` — a
host sees one meter scope; no seventh package, no new meter name). New instruments are created
only when the metering leg registers, so an unregistered add-on creates no instruments and runs
no pipeline code.

**Carrier seams (add-on side, no core change).**

| Need | Seam | Proof at source |
|---|---|---|
| Tagged per-request record at the settled outcome | `IResponseFeature` at `Stage.ShapeResponse` + `context.Response.Body` wrap + `Response.OnCompleted` | `IResponseFeature.cs:9-19` ("before the proxy has copied a single header or body byte to the caller"; wrapping the body stream is ownership-legal); the core audit recorder runs exactly this shape (`CredProxAuditRecorder.cs:100-157`) |
| caller id | `context.Features.Get<CallerIdentity>()` (public) | set at `CallerAuthenticationFeature.cs:115`, read at `CredProxAuditRecorder.cs:131` |
| credential / vendor name | public `CredProxMetadata.GetRouteMetadata` keys `CredProx.Credential` / `CredProx.Destination` | `CredProxMetadata.cs:16,22,55-58` |
| route name | YARP `IReverseProxyFeature` route config `RouteId` | `CredProxAuditRecorder.cs:132,149` (plain YARP surface) |
| final status class | `context.Response.StatusCode` at `OnCompleted` (covers short-circuit and forwarded paths) | `CredProxAuditRecorder.cs:119,153` |
| response bytes | add-on's own counting wrapper on `context.Response.Body` (public API; pattern precedent `CountingResponseBodyStream`, internal, add-on cannot and need not reuse it) | `CredProxAuditRecorder.cs:107-117` |
| request bytes | add-on's own counting wrapper via an `IRequestFeature` at `Stage.Send`, installed on the stream the forwarder pumps: for the content YARP binds (forwarder-owned; it hands out no read stream and replacing the reference trips the forwarder's creation guard — "configure HttpContext.Request instead") the wrapper goes on `HttpContext.Request.Body`, the stream it serializes at send time; content a leg owns wraps through the content with headers copied. Recorded only when the request was forwarded (no short-circuit counts) | forwarder-shape body seam `CredProxRequestState.cs:75-93` (reads and re-installs `HttpContext.Request.Body`; the content reference stays the forwarder's); response-direction wrapper precedent `ResponseScrubFeature.cs:260-274` |
| usage peek of the upstream body, incl. SSE, without buffering | `state.ProxyResponse.Content` stream wrapper installed by the metering response feature, per-event bounded peek — the M20/M22 scrubber is the built-in precedent of a byte-preserving stream owner | `ResponseDispatchHandler.cs:46-50`; `ResponseScrubFeature.cs:260-274`; `EventScrubbingStream.cs:5-27` |
| provider-specific usage parsing | `IUsageReader` (new, `[Experimental]`, in the add-on) — Anthropic reader first; other vendors add their own reader without core involvement | row + owner rule |

**Core delta — the full list.** Five lines, all private, no public surface change, every line
precedented by the Operations sections that already exist:

| File | Change | Why no existing seam carries it |
|---|---|---|
| `CredProxReverseProxyBuilderExtensions.cs:25-29` | add `"Metering"` to the private `CoreSections` set | the root fail-closed walk (M17) rejects every section outside the fixed topology ("CredProx's own add-ons … add no sections" is the comment's own world; `Throttling`/`Resilience`/`Health` are already in this list, so the established route for an add-on-owned section is exactly this line) |
| `CredProxStartupValidator.cs:176-196` | add the metering response-feature name set and one `RejectIfSectionConfigured(errors, "CredProx:Metering", …)` entry | "a configured section whose feature is not registered is refused at startup, not left inert" — only core can see an unregistered add-on; the method already matches registered implementation FullNames through public abstractions (`IEnumerable<IPipelineFeature>`, `IEnumerable<ICredentialHealthProbe>`; metering adds `IEnumerable<IResponseFeature>`, equally public) |

**Rejected placements.**
- *`IAuditSink` only:* the sink rides the audit recorder, which early-returns when auditing is
  disabled or sink-less (`CredProxAuditRecorder.cs:100-103`) — metering would silently vanish
  with audit config, has no request-byte source and no body access for usage parsing.
- *YARP response transforms:* ruled out by the core's own comment — by the time they run, YARP
  has already copied the upstream headers to the caller (`CredProxTransformProvider.cs:20-23`).
- *`IPipelineFeature` `DelegatingHandler`:* sees the settled request/response pair but has no
  `HttpContext` — the per-request state rides an internal `request.Options` key
  (`CredentialAttachFeature.cs:17-29`), so caller/vendor/route tags are unreachable from it.
- *Subclassing `CredProxForwarderHttpClientFactory`:* same tag blindness, plus it re-derives
  pipeline composition a supported seam already provides.
- *A metering package of its own:* adds no outside dependency (Operations already ships
  `System.Diagnostics.Metrics` usage) — ADR-0007 groups by dependency; a seventh package would
  split one meter across assemblies.

## Consequences

- Core gains no public surface from M50; the public-surface witness may only show add-on
  additions, every one `[Experimental("CREDPROX001")]` and listed in CHANGELOG `[Unreleased]`.
- `CredProx:Metering` follows every fail-closed rule the other Operations sections follow:
  unknown keys refused at startup and reload via the public
  `CredProxConfigValidation.RejectUnknownKeysAtStartup` (`CredProx.Operations/.../CredProxOperationsServiceCollectionExtensions.cs:43,90,128`), and a configured section without
  `.AddOperations()` refuses startup naming the package and the call.
- Cardinality is structural, not a runtime cap: every tag value is a configuration name
  (caller id, credential name, destination name, route id) or a fixed status-class bucket;
  unresolvable values collapse to fixed buckets (`anonymous`, `unknown`), never to per-traffic
  strings. A test guards this (§5.2 row addition).
- Metering off means: no leg registered → no instruments, no features, no stream wrappers;
  the bench overhead suite runs metering-off against `baselines/0.15.0`, and the metering-on
  cost is reported, not gated.
- The usage peek wrapper must be byte-preserving by construction (read-and-forward, bounded
  parse window) and is gated by a streaming test that the caller receives identical bytes;
  malformed or oversized usage events degrade to "unmetered", never to a refusal or a stall.
