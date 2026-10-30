# E4 — Spotify: a real public vendor in a few lines of config

## What it demonstrates

A real vendor integration with **no vendor-specific C# at all** and **no presets**: the
credential block spells out Spotify's OAuth facts (token endpoint, Basic client auth, the
secret reference) in plain config, and the host fills in the two values it owns — Client
ID and Client Secret — to reach the Web API catalogue through the proxy. This is the
shape every OAuth vendor takes in CredProx.

## What you need

A free Spotify developer app: <https://developer.spotify.com/dashboard> → *Create app* →
copy the Client ID and Client Secret. No Docker.

## Run it

```bash
export CredProx__Credentials__spotify__ClientId=<your client id>
export CredProx__Secrets__spotify-client-secret=<your client secret>
dotnet run --project samples/Spotify
```

(Development alternative: `dotnet user-secrets --project samples/Spotify set
CredProx:Secrets:spotify-client-secret <secret>` and the same for the ClientId.)

If either value is missing, the host exits and names exactly which one.

Then — **no credential in the request**:

```bash
curl -s http://localhost:5084/spotify/v1/albums/0sNOF9WDwhWunNAHPD3Baj
```

Spotify's JSON for that album comes back. The `Authorization: Bearer …` Spotify saw was
minted by `accounts.spotify.com` for your app, fetched and attached by CredProx.

## The exact config

```jsonc
"CredProx": {
  "Destinations": { "spotify": { "Template": "https://api.spotify.com" } },
  "Credentials": {
    "spotify": {
      "Type": "OAuthClientCredentials",
      "TokenEndpoint": "https://accounts.spotify.com/api/token",
      "ClientId": "",                              // from the environment
      "ClientAuthentication": "BasicHeader",       // Spotify's documented client auth
      "ClientSecret": "secret:spotify-client-secret"
    }
  },
  "Secrets": { "spotify-client-secret": "" }       // value from the environment
}
```

The route `/spotify/{**catch-all}` strips its prefix and names the credential in metadata.
No scope: Spotify's client-credentials grant doesn't take one.

If you talk to Spotify from many hosts, the fixed facts above (endpoint, auth style,
secret name) are exactly what a **preset** packages: put them under `CredProx:Presets`
(or ship an `IPresetSource`) and each credential becomes a `Preset` reference plus the
two values the host owns.

## What just happened

Tracing `curl http://localhost:5084/spotify/v1/albums/0sNOF9WDwhWunNAHPD3Baj`:

1. The route matches, strips `/spotify`, and names credential `spotify`.
2. CredProx POSTs `grant_type=client_credentials` to `accounts.spotify.com/api/token` with
   `Authorization: Basic base64(clientId:clientSecret)` — the secret resolved from the
   `secret:` reference — and caches the returned token for its lifetime.
3. The forwarded request goes to `https://api.spotify.com/v1/albums/…` with
   `Authorization: Bearer <token>`.
4. Spotify answers; the caller's request never carried, and never could carry, the app
   secret.
