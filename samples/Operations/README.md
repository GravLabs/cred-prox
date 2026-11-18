# Operations: throttling, vendor back-off, circuit breaker, health

What running CredProx in production looks like: three clusters behind one host, each
exercising one operational behaviour, all configured — no C# beyond the standard
registration lines in `Program.cs`. WireMock plays the vendor with three personalities
(`wiremock/mappings/`). Needs Docker.

## Run it

```bash
cd samples/Operations
docker compose up -d      # the three-personality WireMock vendor on :8091
dotnet run &              # the host on :5091
./load.sh                 # drives and asserts each behaviour, transcript below
docker compose down
```

`load.sh` is the shortened load script (the nightly NBomber suite holds the rigorous
rate assertions):

```
== 1. Rate limit: 30-request burst against a 5 req/s cluster ==
  client saw: 7x200 23x429 | vendor saw: 7 requests
== 2. Vendor 429 + Retry-After: the cluster pauses ==
  r1=200 r2=429 r3=200 held through the pause r4=200
== 3. Circuit breaker: 500s open it, 503s answer, recovery closes it ==
  f1..f6: 500 500 500 500 503 503 | vendor saw: 4 requests
== 4. Credential health ==
  /health: Healthy
```

## Verify it

One cell per behaviour, driving the real host over real sockets from
`tests/CredProx.SampleSmokes` against WireMock's three personalities:

```bash
dotnet test tests/CredProx.SampleSmokes --filter Sample=Operations
# or the one-line wrapper:
cd samples/Operations && ./smoke.sh
```

The cells: the 30-request burst against `/limited` sheds to 429 and the vendor's counter
proves it never saw the burst; the vendor 429 pauses the `/vendor` cluster for the
advertised `Retry-After` and traffic recovers; four `/flaky` failures open the circuit
(503s, counter frozen) and the half-open probe closes it; `/health` reports Healthy.

## What each cluster shows

**`/limited` — the rate limit protects the vendor.**
`CredProx:Throttling:Clusters:limited` = 5 permits/second, queue of 2, 1 s max wait.
The 30-request burst: a handful pass, two queue briefly, the rest get **429 with
`Retry-After`** (`credprox.throttled`) from CredProx itself — and WireMock's request
counter proves the vendor never saw the burst. Limits are per cluster, never global.

**`/vendor` — a vendor 429 pauses the whole cluster.**
The stub answers its second request with `429` + `Retry-After: 2`. CredProx pauses the
cluster for exactly that long (`PauseOnVendorThrottle`, capped by `MaxPause` so a hostile
header can't wedge a cluster): the next request is held for the advertised interval — the
script times it — and traffic flows again once the pause expires. Queued work waits; work
beyond `MaxQueueWait` gets 429.

**`/flaky` — the circuit breaker stops the bleeding.**
The stub 500s four times, then recovers. `CredProx:Resilience:Clusters:flaky` = failure
ratio 0.5 over ≥ 4 requests, 3 s break. The fourth failure opens the circuit (the ratio is
judged on failure outcomes, so the vendor has to still be failing when the minimum
throughput is met); requests then answer **503** (`credprox.upstream_unavailable`)
**without reaching the vendor** — the counter freezes — and after the break the half-open
probe succeeds and the circuit closes. `MaxRetries: 0` keeps the counting honest; retries
(idempotent methods only) are the default elsewhere.

**`/health` — credential health.**
`AddCredProxHealthProbes` runs the token-obtainable and certificate-expiry probes on a
background loop (here every 5 s) and feeds the `credprox` ASP.NET Core health check. An
expiring client certificate turns it `Degraded` before it expires; a credential that
cannot produce a token turns it `Unhealthy` — and the token probe goes through the cache,
so a healthy credential costs the vendor nothing.

## Try it by hand

```bash
docker compose up -d
dotnet run -- &
./load.sh        # or poke it yourself:
curl -s -o /dev/null -w '%{http_code}\n' localhost:5091/limited   # hammer this
curl -s localhost:5091/health
docker compose down
```

## The config

Everything above lives in one `CredProx` section — `Throttling`, `Resilience` and
`Health` blocks with per-cluster overrides; all three knobs are validated at startup, so
a bad limit fails the deploy instead of surprising you at 3 a.m. See
[appsettings.json](appsettings.json).
