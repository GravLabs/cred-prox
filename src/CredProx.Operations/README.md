# CredProx.Operations

Operations add-on for [CredProx](https://github.com/GravLabs/cred-prox):

- **Outbound throttle** (`CredProx:Throttling`) — per-YARP-cluster rate and concurrency
  limits with a bounded queue; a full queue or an exceeded wait answers 429 with
  `Retry-After` (`credprox.throttled`), and a vendor 429 pauses its cluster for the
  advertised duration.
- **Resilience adapter** (`CredProx:Resilience`) — attempt timeout, retry (idempotent
  methods only unless `RetryNonIdempotent` with a body buffered within the cap) and a
  per-cluster circuit breaker; an open circuit answers 503
  (`credprox.upstream_unavailable`) without reaching the upstream, and half-opens after
  the break duration.
- **Credential health probes** (`CredProx:Health`) — token obtainable (through the core's
  token cache, so a valid cached token costs no vendor call) and certificate expiry, on a
  background loop feeding the `credprox` ASP.NET Core health check, the `CredProx` meter's
  health gauges and transition warnings. With `CredProx:Health:Enabled=false` neither the
  probe loop nor the `credprox` check is registered — off is off.

Pipeline order is unchanged: the features keep their `Stage.Pipeline` placement with
resilience innermost (`Order 0`) inside one throttle permit (`Order 10`), after signing
and the core stages. Caller budgets and the kill switch stay core caller policy.

## Setup

```csharp
builder.Services.AddCredProx(configuration)
    .AddOperations();
```

One chained call arms all three legs — and each leg arms only when its own section is
present: no `CredProx:Throttling`, no limiter; no `CredProx:Resilience`, no retry or
breaker; no `CredProx:Health`, no probes.

Configuration is unchanged from the core era (`CredProx:Throttling`,
`CredProx:Resilience`, `CredProx:Health` — see the
[`Operations`](https://github.com/GravLabs/cred-prox/tree/main/samples/Operations)
sample). Configuring one of those sections without this package registered fails startup
naming the package to add — a configured limit never sits inert.

## Install

```bash
dotnet add package CredProx.Operations
```

Installs beside `CredProx`; the core package README carries the package map.

## License

MIT
