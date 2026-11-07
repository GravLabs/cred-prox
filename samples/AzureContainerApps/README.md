# AzureContainerApps — M29 round-2 host (one image, three modes)

The plan's round-2 test host (`docs/azure-live-test-plan.md` §Round 2): one
container image that can act as the CredProx **proxy**, the **counterparty**
(three independent verifiers), or the in-cluster **battery**. The live run
deploys proxy + counterparty as one internal-only Container App and drives the
battery as a Container Apps Job — zero public listeners anywhere (G2).

## Modes

| Invocation | Role |
|---|---|
| `--mode proxy` | CredProx forwarder on `ASPNETCORE_URLS`. Routes: `/arm/*` (TokenCredential → ARM with the managed identity), `/jwt/*`, `/hmac/*`, `/mtls/*` → counterparty. Every route demands a caller key. |
| `--mode counterparty` | The verifiers: RS256 client-assertion check against the PINNED public key, independent HMAC canonical-string recomputation, mTLS client-cert chain pinned to the CA + CN echo. Owns its ports in code (`8082` http, `8443` https strict client-cert). |
| `--mode battery --proxy https://<internal-fqdn> [--phase all\|jwtprobe]` | Console probe, no listener. Prints one `P<n> PASS/FAIL` line per plan phase (`all`) or just the JWT-lifetime probe (`jwtprobe`, for the rotation witness). Caller key from vault secret `CredProx--Secrets--caller-key` (needs `KeyVault__Uri` + identity) or `CREDPROX_SMOKE_CALLER_KEY`. Strict TLS — an internal-ingress chain failure is a finding, not retried around. |
| `--mode proxy --smoke` | Offline proof in one process: counterparty + proxy + battery checks with generated material, no vault, no Azure. Exit 0 prints `SMOKE OK:`. |
| `--mode reloadproof` | Offline VAULT-PROVIDER RELOAD proof: the real provider + a real `SecretClient` + its real polling loop poll a loopback Key-Vault REST stub (`tools/keyvault-stub.py`) with ONLY the transport swapped. Rewrite the stub's file mid-run: the reload token fires and the value changes without a restart. Exit 0 prints `RELOAD PROOF OK`. Recipe below. |

## Build and offline proof

The example consumes the packed packages from `artifacts/packages` — pack
first (the Dockerfile header lists these too):

```bash
dotnet pack src/CredProx.Abstractions -c Release -o artifacts/packages
dotnet pack src/CredProx -c Release -o artifacts/packages
dotnet pack src/CredProx.AzureKeyVault -c Release -o artifacts/packages
docker build -f samples/AzureContainerApps/Dockerfile -t credprox-m29:latest .
docker run --rm credprox-m29:latest --mode proxy --smoke
```

`P5 PASS … P9 PASS` + `SMOKE OK` is the G1 offline gate. The full live gate
list lives in the plan (§Round 2); `scripts/live-*.sh` drive it — **only**
after the maintainer's gate, nothing here mutates Azure by itself.

The offline **reload** proof (no Azure, no tenant; Linux docker):

```bash
mkdir -p /tmp/kvdata && printf 'first-value' > /tmp/kvdata/CredProx--Secrets--proof.txt
python3 samples/AzureContainerApps/tools/keyvault-stub.py --data /tmp/kvdata &
docker run --rm --network host \
  -e KeyVault__Uri=https://credprox-m29-stub.vault.azure.net/ \
  -e CREDPROX_RELOAD_SECONDS=5 -e CREDPROX_PROOF_SECONDS=60 \
  credprox-m29:latest --mode reloadproof
# mid-run, from this host:
printf 'rotated-value-1' > /tmp/kvdata/CredProx--Secrets--proof.txt
```

`RELOAD TOKEN FIRED; CredProx:Secrets:proof = rotated-value-1` +
`RELOAD PROOF OK` is the gate. reloadproof uses the real provider and
SecretClient with a transport swapped to a loopback stub: it proves the
reload mechanism (polling → change detection → reload token → value swap in
the running process), not Azure-side latency.

## Configuration truth

- Secret material arrives ONLY from Key Vault through the stock provider
  chain (`AddAzureKeyVault` + `AddCredProxConfigurationSecrets`, the shipped
  MicrosoftGraph pattern): vault secret `CredProx--Secrets--<name>` answers
  `secret:<name>` in `appsettings.json`. Consumed: `jwt-signing-key`,
  `hmac-key`, `mtls-client-cert` (+`-password`), and on the counterparty
  `cp-server-cert` (+`-password`); the battery reads `caller-key`. Pinning
  material (`CredProxTest--jwt-public`, `CredProxTest--mtls-ca`) comes from the same
  vault but is PUBLIC by design.
- The caller registry arrives as plain env config
  (`CredProx__Callers__battery__Keys__0__KeyHash=sha256:<hex>`). The registry
  stores only the SHA-256 hash — the key VALUE is not config, only a vault
  secret the battery fetches. The container trust anchor for the counterparty
  server cert is the PUBLIC test-CA (`CREDPROX_TEST_CA_PEM_B64` →
  `update-ca-certificates` in the entrypoint); no secret travels that path.
- **Metadata placement matters**: `CredProx.Connection` is a CLUSTER metadata
  (the connection certificate attaches to the forwarding HttpClient — see
  `CredProxForwarderHttpClientFactory`, and the MutualTls sample);
  `CredProx.Destination` / `CredProx.Credential` are ROUTE metadata. Wrong
  placement starts clean but attaches nothing — the smoke run catches it.
- **Egress prefix**: the CredProx destination `Template`
  (`CredProx:Destinations:<name>:Template`) is authoritative — the CredProx
  transform overwrites YARP's cluster `Address` per request. Keep both
  consistent (they are here and in the deploy config).
- `/arm` strips its prefix (real ARM wants `/subscriptions`); `/jwt`, `/hmac`,
  `/mtls` forward the full path — the counterparty is namespaced by prefix and
  its HMAC verifier signs/verifies the received path.
- **2+ managed identities on one Container App:** set
  `ManagedIdentityClientId` **in code** (the credential options). With a
  single UAI the platform picks it; with two or more, nothing on the ACA
  managed-identity wire ever sees an env-level hint and identity selection is
  silently ambiguous. Live finding 2026-11-06.
- **ACR pull:** the pull identity must be BOTH attached
  (`az containerapp identity assign`) AND selected via
  `configuration.registries[].identity` — an environment-level identity does
  not pull images, for the app or for a Job. Live finding 2026-11-06.

## Honesty notes

- Smoke **P5** runs against an in-proc ARM stub: route + caller-auth +
  forwarding only, NOT the managed identity. The MI path is proven only by
  the live battery P5 against real ARM.
- Smoke runs the arm credential as a fixed-token stub
  (`SmokeTokenCredential`) — no Azure environment exists in the container.
- The pinned verifiers prove signature/chain CORRECTNESS with independent
  code — they do not assert vendor trust, and the Keycloak-style claim
  "vendor verified the client assertion" is not made anywhere.
- The vault is treated as a custodian/deliverer only — no HSM, no
  never-exports claim is made about the keys (they travel as PEM/PFX to the
  consuming process, which is what this test is actually about).
- A rotated vault value reaches a running process only because
  `AddAzureKeyVault` is called with `ReloadInterval` set (all sites here set
  30s); the provider default never polls. Without it (or a restart), the old
  value is served forever.
