# E1 — QuickStart: a static key, attached by the proxy

## What it demonstrates

The smallest useful CredProx host: one route, one destination, one credential. The caller
sends **no credential at all**; CredProx attaches a static API key to the forwarded request
because the route's metadata names the credential. This is the "the key lives in one place,
the proxy, not in every client" pattern.

## What you need

Nothing but the .NET SDK. The example proxies to the public `postman-echo.com` echo service,
which shows back the headers it received. No accounts, no Docker.

## Run it

```bash
dotnet run --project samples/QuickStart
```

Then, in another terminal — note there is **no credential in this request**:

```bash
curl -s http://localhost:5080/echo/headers
```

The response is postman-echo's JSON, and it contains:

```json
{ "headers": { "x-api-key": "demo-static-key", ... } }
```

The `X-API-Key` header was added by CredProx. The caller never had it.

## The exact config

Everything is in `appsettings.json` — no vendor-specific C#:

```jsonc
"CredProx": {
  "Destinations": {
    "echo": { "Template": "https://postman-echo.com" }
  },
  "Credentials": {
    "echo-key": {
      "Type": "StaticKey",
      "Name": "X-API-Key",
      "Secret": "secret:echo-key"      // a secret: reference, never a literal in route config
    }
  },
  "Secrets": {
    "echo-key": "demo-static-key"      // demo only — see "Where secrets belong" below
  }
},
"ReverseProxy": {
  "Routes": {
    "echo": {
      "ClusterId": "echo",
      "Match": { "Path": "/echo/{**catch-all}" },
      "Transforms": [ { "PathRemovePrefix": "/echo" } ],
      "Metadata": {
        "CredProx.Destination": "echo",     // which destination rule applies
        "CredProx.Credential": "echo-key"   // which credential to attach
      }
    }
  },
  "Clusters": {
    "echo": { "Destinations": { "echo": { "Address": "https://postman-echo.com/" } } }
  }
}
```

The five lines of C# in `Program.cs` are the standard CredProx service block — identical in
every example.

## Where secrets belong

`CredProx:Secrets` in `appsettings.json` is fine for a demo. In production put the same keys
in environment variables (`CredProx__Secrets__echo-key`), user-secrets in development, or a
key-per-file directory (`AddKeyPerFile`) — the `secret:` reference resolves through the
ordinary `IConfiguration`, so any configuration provider works.

## Verify it without internet

Two stand-ins for `postman-echo.com`, both showing the same thing:

```bash
# In-process stand-in — no Docker, no build order concerns:
dotnet run --project samples/QuickStart -- --smoke

# WireMock stand-in (what CI runs):
cd samples/QuickStart && ./smoke.sh
```

`--smoke` swaps the destination for an in-process echo endpoint; `smoke.sh` starts the
WireMock container from `docker-compose.yml` and repoints the destination at it purely with
environment variables (`CredProx__Destinations__echo__Template=…`) — no config file changes.
Both print `SMOKE OK` when the upstream saw the `X-API-Key` header.

## What just happened

Tracing `curl http://localhost:5080/echo/headers`:

1. YARP matches the `echo` route (`/echo/{**catch-all}`) and strips the `/echo` prefix.
2. The route metadata says `CredProx.Credential=echo-key`, so CredProx resolves that
   credential binding.
3. The binding is a `StaticKey` whose `Secret` is the reference `secret:echo-key`; the
   configuration secret source resolves it to the configured value.
4. CredProx attaches `X-API-Key: demo-static-key` to the forwarded request and applies the
   destination template, so it goes to `https://postman-echo.com/headers`.
5. The caller's request carried no credential; the upstream received one. That difference is
   the entire product.
