#!/usr/bin/env bash
# Populate a run directory: per-run sentinel secrets + caller keys (hashed into the host
# config), templated WireMock mappings, and the secret-scan pattern list. Nothing here
# leaves the run dir; the repo keeps only placeholders.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="${1:?usage: init-secrets.sh <run-dir>}"
mkdir -p "$RUN/host-config" "$RUN/wiremock" "$RUN/logs"

python3 -I - "$ROOT" "$RUN" <<'PY'
import json, hashlib, secrets, sys, pathlib
root, run = sys.argv[1], sys.argv[2]
def tok(): return "soak-" + secrets.token_hex(16)
secrets_map = {k: tok() for k in
    ["vendor-gen1-key", "vendor-gen2-key", "stream-key", "idp-client-secret", "login-password"]}
keys = {n: tok() for n in ["a", "b", "c"]}
probe = secrets_map["vendor-gen1-key"]
def h(k): return "sha256:" + hashlib.sha256(k.encode()).hexdigest()

conf = pathlib.Path(root, "SoakHost", "appsettings.json").read_text()
conf = (conf.replace("SEC_GEN1", secrets_map["vendor-gen1-key"])
            .replace("SEC_GEN2", secrets_map["vendor-gen2-key"])
            .replace("SEC_STREAM", secrets_map["stream-key"])
            .replace("SEC_IDP", secrets_map["idp-client-secret"])
            .replace("SEC_LOGIN", secrets_map["login-password"])
            .replace("KEYHASH_A", h(keys["a"]))
            .replace("KEYHASH_B", h(keys["b"]))
            .replace("KEYHASH_C", h(keys["c"])))
json.loads(conf)  # refuse to write broken config
pathlib.Path(run, "host-config", "appsettings.json").write_text(conf)

idp_tok, login_sid = tok(), tok()
kv_val, kv_rotated = tok(), tok()
for m in pathlib.Path(root, "wiremock", "mappings").glob("*.json"):
    body = (m.read_text().replace("IDP-TOKEN-SENTINEL", idp_tok)
                        .replace("LOGIN-SESSION-SENTINEL", login_sid)
                        .replace("KV-GEN2-SENTINEL", kv_val)
                        .replace("KV-GEN2-ROTATED", kv_rotated))
    pathlib.Path(run, "wiremock", m.name).write_text(body)

pathlib.Path(run, "keys.txt").write_text(json.dumps(
    {"a": keys["a"], "b": keys["b"], "c": keys["c"], "probeSecret": probe}))
with pathlib.Path(run, "sentinels.txt").open("w") as f:
    for v in list(secrets_map.values()) + list(keys.values()) + [idp_tok, login_sid, kv_val, kv_rotated]:
        f.write(v + "\n")
print("INIT-SECRETS-DONE")
PY
