# M54 step 0 — Foundry Local measured findings

Measured 2026-11-23 on a Foundry Local 2.5.0 CPU server:
`http://127.0.0.1:5273/v1`, loopback-only, no auth, one loaded model
`qwen3-4b-generic-cpu:3` (a thinking model). One request at a time, small
prompts: shared CPU inference. This is measurement, not design — no sample or
code claims live here.

Server identity seen in the wire itself: `server: oatpp/1.3.0` (from its 404 bodies).

## Product framing (Microsoft docs, for the design that follows)

- Foundry Local is an end-to-end local AI stack: SDK (C#, C++, JavaScript, Rust,
  Python), a curated model catalog, and automatic hardware acceleration. Its API is
  "OpenAI-compatible — Supports OpenAI request and response formats"; the web server
  is an *optional* component for serving models to multiple processes and dev
  workflows, while Microsoft steers embedded apps to the in-process SDK ("For most
  embedded application scenarios, use the SDK directly").
  <https://learn.microsoft.com/en-us/azure/foundry-local/what-is-foundry-local>
- Official REST reference for the server: endpoints and chat/completions request and
  response fields. <https://learn.microsoft.com/en-us/azure/foundry-local/reference/reference-rest>
- Official tool-calling loop (any language): detect `response.choices[0].message.tool_calls`,
  execute, "add a message with role `tool` and the matching `tool_call_id`", ask again.
  <https://learn.microsoft.com/en-us/azure/foundry-local/tutorials/tutorial-build-tool-calling-assistant>
- Repository and samples: <https://github.com/microsoft/Foundry-Local> (links printed
  by the Foundry blog); .NET SDK package `foundry-local-sdk` (Microsoft, 2.5.0)
  <https://www.nuget.org/packages?q=foundry-local>; announcement posts and updates:
  <https://devblogs.microsoft.com/foundry/category/foundry-local/> (Build 2025
  announcement; Android + simpler-SDK post
  <https://devblogs.microsoft.com/foundry/foundry-local-comes-to-android/>).
- Docs root: <https://learn.microsoft.com/en-us/azure/foundry-local/>

## 1. Non-streaming chat — usage fields

`POST /v1/chat/completions` → 200. Response is the OpenAI chat.completion shape.
`usage` is always present on non-stream responses (none without usage was seen),
with OpenAI-style nesting beyond the plain trio:

```json
"usage": {"completion_tokens": 32,
          "completion_tokens_details": {"reasoning_tokens": 31},
          "prompt_tokens": 13,
          "prompt_tokens_details": {"cached_tokens": 0},
          "total_tokens": 45}
```

- `max_tokens` counts reasoning tokens too: at `max_tokens: 32` the model spent 31
  tokens reasoning, `finish_reason` was `length` and `content` was `""`. The docs
  note the same trap and suggest `max_completion_tokens` ("For newer models, use
  max_completion_tokens... including visible output and reasoning tokens") —
  reference page above. Practical floor for this model: ~800 tokens for short
  answers (reproduced: content empty at 32, real answers at 800).
- `finish_reason` observed: `stop`, `length`, `tool_calls`.
- The REST reference documents the three plain usage fields; the
  `*_tokens_details` nesting is measured here, not in the reference example.

## 2. Streaming

`stream: true` → SSE. Framing as measured:
- A leading `: keep-alive` comment line before the first event.
- Each event is a single `data: {json}` line, `object: "chat.completion.chunk"`,
  stable `id` per request; `choices[0].delta` carries `role` (first chunk), then
  `reasoning_content` fragments (this model) and/or `content` fragments.
- Final content event: empty `delta`, `finish_reason` set.
- Terminator: `data: [DONE]`.

`usage` on the stream:
- Without `stream_options`: NO usage chunk at all (0 occurrences across 202 data
  lines of a streamed answer).
- With `stream_options: {"include_usage": true}`: exactly one extra event AFTER the
  finish_reason event: `"choices": []` plus the `usage` object (including
  `completion_tokens_details.reasoning_tokens`), before `[DONE]`.

A metering reader must therefore request `include_usage` explicitly to see usage on
a streamed call, and must treat the `choices: []` chunk as usage-only, not an answer.

## 3. Tool calling

OpenAI tool shape works end-to-end on this server:
- Request: `tools: [{"type":"function","function":{"name","description","parameters":<JSON schema>}}]`.
- Turn 1 response: `finish_reason: "tool_calls"`, `message.tool_calls:
  [{"id":"call_...","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]`
  (`arguments` is a JSON **string**). Note `content` was `"\n\n"` alongside the
  calls — a sample must not assume empty content when tool_calls are present.
- Turn 2 request: replay the assistant message with its `tool_calls`, then a
  `{"role":"tool","tool_call_id":"call_...","content":"18C and sunny"}` message →
  final answer, `finish_reason: "stop"`. This matches the documented loop (link
  above) step for step.
- The REST reference's request example lists only the legacy `functions` /
  `function_call` fields; the modern `tools` shape is what this server accepts —
  measured behaviour is the authority here.

## 4. Auth

- No `Authorization` header at all → 200 (every measured call).
- `Authorization: Bearer <a fake three-segment JWT-shaped value>` → 200.
- `api-key: <bogus>` → 200.

Headers are ignored, not required: the server neither validates nor rejects them,
so whatever a caller sends through CredProx reaches the model unchecked — CredProx
is the only gate. (The `token` field in the REST reference belongs to protected
model DOWNLOADS, not to inference requests.)

## 5. Error shapes

OpenAI-style envelope: `{"error":{"code":null,"param":null,"message":"...","type":"invalid_request_error"}}`
- Unknown model → **404**, `message: "Model not found: No model matching '<id>'"`,
  `type` stays `invalid_request_error` (not `model_not_found`).
- Malformed body (`messages` as a string) → **400**, message embeds the native
  JSON library's `type_error.302` text.

A gateway relaying these must not assume the exact OpenAI `type` codes; the message
string is the reliable part, and status is 404 vs 400.

## 6. Thinking output

Reasoning appears as a **separate `reasoning_content` field** — on
`message.reasoning_content` (non-stream) and on `delta.reasoning_content`
(stream). It never rides inside `content` as tags on this model, and
`usage.completion_tokens_details.reasoning_tokens` counts it. An agent sample must
read `content` for the answer, may surface or drop `reasoning_content`, and must
not read empty `content` + heavy reasoning as a failure.

## Deployment shape of THIS server (measured; not the library's full surface)

- Exposed: `/v1/models`, `/v1/chat/completions` (the two endpoints everything above
  used).
- Not exposed here (both 404 from the oatpp router): `/openai/status`
  and `/v1/chat/completions/tokenizer/encode/count` — both are documented in
  the REST reference above, so they
  belong to the full CLI REST server, not to this inference-only deployment. The documented default port in the reference example is 5272; this
  deployment binds 5273.
- `/v1/models`: OpenAI list shape, 51 entries
  `{id, object:"model", created, owned_by:"Microsoft"}`; there is NO
  cached/available flag in the entries — the catalog-vs-cached distinction is not
  representable through `/v1/models` on this server.

## Unverified — stays out of the samples unless measured later

- Over-context request shape: deliberately not measured — a ~40k-token CPU prefill
  is not cheap on this shared box, and the tokenizer-count endpoint that could
  estimate it is not exposed here.
- A catalog-but-uncached model id: deliberately not requested — it could trigger a
  multi-GB download attempt; this deployment is configured never to download.
- The Responses API format on this server (documented for the product, endpoint not
  probed).
- `n > 1`, `stop` sequences, `logit_bias`, temperature boundaries, `seed`.
- Non-zero `prompt_tokens_details.cached_tokens` (only 0 observed).
- Concurrency behaviour of this deployment under parallel requests.
