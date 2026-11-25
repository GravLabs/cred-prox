# ADR-0009: Usage format chosen per route; Foundry Local examples (M54)

Status: Accepted (2026-11-24, with the M54 merge)

## Context

M54 adds examples against Foundry Local, Microsoft's local model server, which speaks the
OpenAI chat-completions format (`docs/foundry-local-notes.md` holds the measured facts). The plan
row asks for an OpenAI-format usage reader behind `IUsageReader` (ADR-0008) and three samples:
a local gateway, the M53 agent pattern on a local model, and local plus cloud.

The M50 reader selection cannot carry a second vendor format. The metering response feature
takes the first registered `IUsageReader` whose `CanRead(mediaType)` accepts the response
(`CredProxMeteringResponseFeature.cs` `SelectReader`), and the built-in Anthropic readers are
registered first and claim `application/json` and `text/event-stream`. An OpenAI reader, or
any host reader for those media types, would therefore never be chosen: OpenAI responses
would be unmetered, silently. A media type does not say which vendor's body shape follows.

Measured facts that shape the reader (from the notes):
- Non-streaming: `usage.prompt_tokens`, `usage.completion_tokens`, with
  `completion_tokens_details.reasoning_tokens` already counted inside `completion_tokens`.
- Streaming: usage appears only when the caller sends `stream_options.include_usage: true`,
  as one extra `choices: []` event before `data: [DONE]`.
- The server ignores every auth header, so CredProx is the only gate.

## Decision

**Format named per route.** The opt-in route metadata `CredProx.Metering.Usage` takes a usage
format name instead of `true`: `anthropic` or `openai` for the built-ins, or the name a host
reader declares. `IUsageReader` gains `string Format { get; }`. The feature picks the first
reader whose `Format` equals the route's value (ordinal, case-insensitive) and whose `CanRead`
accepts the media type. `IUsageReader` is unreleased (`CHANGELOG.md` `[Unreleased]`), so this
breaks no shipped consumer. The existing samples move from `true` to `anthropic`.

**Fail closed on a bad name.** A route whose `CredProx.Metering.Usage` value names no
registered format is refused at startup and on reload, naming the route and the value, the
same way the other Operations sections refuse unknown keys. `true` is not kept as an alias:
there is no shipped consumer of it, and one spelling is easier to audit.

**Built-in OpenAI readers** in `CredProx.Operations`, internal, beside the Anthropic ones:
- JSON: input = `usage.prompt_tokens`, output = `usage.completion_tokens`. Reasoning tokens are
  not added again, because they are already inside `completion_tokens`.
- SSE: read only the usage-only event (`choices` empty and `usage` present) before `[DONE]`.
- The same trust rules as the Anthropic readers: the documented shape only, a non-positive or
  non-integer count is not reported, nothing guessed, and the bounded parse window applies.

**CredProx does not add `stream_options` to a caller's request.** Rewriting request bodies is a
new capability with its own risks: the caller would see a stream shape it did not ask for, and
every body-size and scrub guarantee would need re-proving. A streamed OpenAI-format call
without `include_usage` is unmetered, and the docs say so. Samples send it.

**Samples, no core change, no new package:**
1. *Local gateway:* an AiGateway-shaped sample whose upstream is Foundry Local, with per-caller
   keys, operation allow-lists, and the `openai` usage format. The upstream takes no
   credential, so the README states that CredProx is the only gate and that the endpoint must
   stay reachable only from the CredProx host (loopback here).
2. *Agent on a local model:* the M53 agent pattern (its own Entra token only, tools through
   CredProx, a disallowed tool refused with 403) with Foundry Local as the model, so a live
   run costs nothing per call. The agent reads `content` for the answer and never treats empty
   content beside `reasoning_content` as a failure. It allows enough completion budget for a
   thinking model.
3. *Local plus cloud:* one CredProx front with a local route for everyone and a cloud
   (Anthropic) route that only named callers' allow-lists reach. The choice is config routes
   and allow-lists, not code. This is **not automatic failover**: if the local model fails,
   the call fails. The README says so in its first paragraph, because "fallback" invites the
   wrong expectation.

## Rejected

- *One JSON reader that accepts both vendors' field names:* it reads shapes the route never
  promised, and the OpenAI Responses format uses `input_tokens`, the Anthropic spelling, so a
  union reader can misread a vendor it was not told about.
- *Content sniffing in `CanRead`:* `CanRead` sees only the media type, and widening it to body
  bytes breaks the never-buffer rule of ADR-0008.
- *A per-host global format option:* a host with one Anthropic and one local route, sample 3
  exactly, needs a per-route choice.
- *Automatic failover to the cloud on local errors:* that is new routing code, it makes a
  billable call happen without a caller asking for the cloud model, and the owner asked for
  config-chosen routing (plan row M54).

## Consequences

- The M50 docs (`docs/metrics.md`, the AiGateway and AgentTokens READMEs) change `true` to a
  format name, and the CHANGELOG `[Unreleased]` entry names `IUsageReader.Format`.
- A host reader for any vendor now works on JSON and SSE routes, which the M50 shape silently
  prevented. A cell proves that a host reader with its own format name wins on its route
  while the built-ins keep theirs.
- Live runs for samples 1 and 2 hit only the loopback model and spend nothing. Sample 3's cloud
  leg makes a few billable calls and needs the owner's go-ahead first.
