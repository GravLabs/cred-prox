# Metrics reference (usage metering)

CredProx can emit per-caller, per-vendor usage metrics on its existing `"CredProx"` meter
(version `0.1.0`, shared with the Operations health signals), so an operator can see who uses
which vendor and how much without a paid gateway analytics tier. Metering is a behaviour of
`CredProx.Operations`: it is armed by the presence of a `CredProx:Metering` configuration
section together with `.AddOperations()` — the same fail-closed rule as the throttling,
resilience and health legs (a configured section without the registration refuses startup, and
an unregistered add-on creates no instruments and runs no pipeline code).

## Instruments

| Instrument | Kind | Unit | Meaning |
|---|---|---|---|
| `credprox.requests` | counter | — | Forwarded requests. Short-circuited requests (a CredProx refusal before forwarding) are never counted. |
| `credprox.request.bytes` | histogram | `By` | Request body bytes forwarded upstream. Not recorded for bodyless requests. |
| `credprox.response.bytes` | histogram | `By` | Response body bytes delivered to the caller, including stream fragments delivered before an abort. |
| `credprox.usage.input_tokens` | counter | `{token}` | Input tokens from the provider's own usage report. Opted-in routes only. |
| `credprox.usage.output_tokens` | counter | `{token}` | Output tokens from the provider's own usage report. Opted-in routes only. |

## Tags

The three byte/token instruments and the request counter carry exactly these tags:

| Tag | Value |
|---|---|
| `credprox.caller` | The caller name from configuration. A request CredProx forwarded without caller authentication is tagged `anonymous`. |
| `credprox.credential` | The credential name the outbound request used, from route metadata (`CredProx.Credential`). `unknown` when the route names none. |
| `credprox.destination` | The destination name from route metadata (`CredProx.Destination`). `unknown` when the route names none. |
| `credprox.route` | The YARP route id. |
| `credprox.status_class` | The settled response status bucket: `1xx`…`5xx`, or `unknown` for anything outside 100–599. |

Token counters carry the four name tags (caller, credential, destination, route) and no status
class — usage is read from the provider report before the caller-side outcome is settled.

Every tag value is a configuration name or a fixed bucket. A key, token, header value, path
parameter or any other per-traffic string never becomes a tag, so series cardinality is
bounded by configuration, not by traffic.

## Token usage (opt-in per route)

Usage tokens are read from the provider's own usage report in the response — CredProx never
guesses. A route opts in by naming its usage format in route metadata:

```yaml
metadata:
  CredProx.Metering.Usage: "anthropic"
```

The value NAMES a usage format. `anthropic` and `openai` are built in; a host can name the
`Format` of its own `IUsageReader`. Selection matches the named format first and the
response media type second, so vendors that share a media type never compete. A route
naming a format no registered reader declares is refused at startup and on every
configuration reload, naming the route id and the value — metering configuration that
cannot be served never sits inert.

The `anthropic` format reads reports out of the box, both non-streaming (`usage` on the
JSON response) and streaming (`message_start` / `message_delta` events). An SSE event with
no `type` field is not metered: a `usage` object on an untyped event is ignored and the
response stays unmetered for tokens — a vendor variant that reports usage on untyped
events registers its own `IUsageReader`; CredProx does not guess an event's kind. The
`openai` format reads the non-streaming `usage` object (`prompt_tokens` /
`completion_tokens`; detail objects such as `completion_tokens_details.reasoning_tokens`
are already included upstream and never added again) and, when streaming, exactly the
usage-only event: empty `choices` plus `usage`. An OpenAI stream that never carries that
event — the default unless the caller sets `stream_options.include_usage` — is counted
normally for bytes but stays unmetered for tokens. A response that carries no
usage is counted normally but stays unmetered for tokens. The peek is bounded by
`CredProx:Metering:MaxUsageParseBytes` (default 1 MiB): reading stops at the window, the
caller's bytes are unaffected, and the request stays unmetered. Other vendors add tokens by
registering their own `IUsageReader` (`CredProx.Operations`, experimental) — no core change.

Raising the window is not free CPU: the non-streaming JSON reader re-walks the whole held
prefix as each chunk arrives, so cost grows super-linearly with the window — measured at
19 ms for a full 1 MiB window against 1334 ms at 16 MiB (16× the bytes, about 70× the time).
At the 64 MiB validator ceiling, an opted-in JSON response whose usage arrives late can cost
tens of CPU-seconds; keep the 1 MiB default unless a provider really reports usage beyond it.
A metered streaming response also allocates about 2.7 KiB more than the same response
unmetered — the cost of the opt-in is bytes and CPU, never the caller's bytes.

Token counting never buffers a streamed response: the usage peek forwards every byte to the
caller as it reads, and malformed or oversized usage events degrade to unmetered, never to a
refusal or a stall.

## Collection

Metrics ride the standard `System.Diagnostics.Metrics` infrastructure, so any host already
collecting .NET metrics picks CredProx up by adding the meter:

```csharp
// OpenTelemetry SDK, alongside AddCredProx(...).AddOperations()
builder.Services.AddOpenTelemetry().WithMetrics(m => m
    .AddMeter("CredProx")
    .AddOtlpExporter());
```

`samples/AiGateway` carries a complete local setup: OTLP export by default, and the console
exporter (metrics printed to stdout) by configuration.

## What metering never does

- Never tags with anything secret (keys, tokens, header values, path parameters).
- Never changes what the caller receives: a metering failure logs a warning and loses counts,
  never bytes. The disposal swallows are the deliberate silent exception: when the vendor
  stream refuses to close inside the metering response wrapper (sync or async), the usage
  record has already been made and the caller already has its bytes, so there is nothing
  left for the caller to lose and no warning is logged — a disposal throw there is silent
  by design and says only "the vendor stream would not close".
- Never meters a request CredProx itself refused — refusals are observable through their own
  problem documents and audit records, not metrics.
- Never adds behaviour when unregistered: no `CredProx:Metering` section (or no
  `.AddOperations()`) means no instruments, no features, no stream wrappers.
