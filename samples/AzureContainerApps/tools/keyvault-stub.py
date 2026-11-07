#!/usr/bin/env python3
"""Loopback Azure Key Vault REST stub for --mode reloadproof (dev/proof tooling only).

Serves exactly the endpoints the pinned Azure provider (Azure.Extensions.AspNetCore.
Configuration.Secrets 1.3.2) polls:

  GET /secrets?api-version=...           paged SecretProperties list (nextLink null)
  GET /secrets/{name}[/{version}]        Secret value (contentType null -> raw string)

One *.txt file in --data is one secret: filename (minus .txt) is the secret name, the
bytes are the value. The provider's change detection compares SecretProperties.updated
to the previously loaded UpdatedOn (AzureKeyVaultConfigurationProvider.IsUpToDate), so
attributes.updated is the file mtime - rewriting a file bumps it, the running provider
re-fetches the value and fires its reload token. The version token is content-derived
(sha256 prefix); the id host comes from X-Stub-Vault-Host (fallback Host header) so
returned ids parse against the real-form https vault URI the client was built with.

Never deployed. No auth - the Bearer header is ignored; this proves the provider
POLLING MECHANISM offline, nothing about Azure-side behaviour.

Run: python3 keyvault-stub.py --data /tmp/kvdata --port 18300
"""
import argparse
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse


class Handler(BaseHTTPRequestHandler):
    data_dir = "."
    default_host = "credprox-m29-stub.vault.azure.net"

    def vault_host(self):
        return (self.headers.get("X-Stub-Vault-Host")
                or self.headers.get("Host", self.default_host).split(":")[0]
                or self.default_host)

    def secret_file(self, name):
        # Names are filesystem-safe by construction (CredProx--* pattern); refuse traversal.
        if "/" in name or "\\" in name or name.startswith("."):
            return None
        path = os.path.join(self.data_dir, name + ".txt")
        return path if os.path.isfile(path) else None

    @staticmethod
    def version_of(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:12]

    def json_reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        parts = [unquote(p) for p in parsed.path.strip("/").split("/")]
        host = self.vault_host()

        if parts == ["secrets"]:
            value = []
            for entry in sorted(os.listdir(self.data_dir)):
                if not entry.endswith(".txt"):
                    continue
                name, path = entry[:-4], os.path.join(self.data_dir, entry)
                updated = int(os.path.getmtime(path))
                ver = self.version_of(path)
                value.append({
                    "id": f"https://{host}/secrets/{name}/{ver}",
                    "contentType": None,
                    "managed": False,
                    "attributes": {"enabled": True, "created": updated, "updated": updated,
                                   "recoveryLevel": "Purgeable"},
                })
            self.json_reply(200, {"value": value, "nextLink": None})
            return

        if len(parts) >= 2 and parts[0] == "secrets":
            name, path = parts[1], self.secret_file(parts[1])
            if path is None:
                self.json_reply(404, {"error": {"code": "SecretNotFound",
                                                "message": f"Secret {name} not found"}})
                return
            ver = self.version_of(path)
            if len(parts) == 3 and parts[2] != ver:
                self.json_reply(404, {"error": {"code": "SecretVersionNotFound",
                                                "message": f"Version {parts[2]} not found"}})
                return
            updated = int(os.path.getmtime(path))
            with open(path, "r", encoding="utf-8") as f:
                secret_value = f.read()
            self.json_reply(200, {
                "value": secret_value,
                "id": f"https://{host}/secrets/{name}/{ver}",
                "contentType": None,
                "managed": False,
                "attributes": {"enabled": True, "created": updated, "updated": updated,
                               "recoveryLevel": "Purgeable"},
            })
            return

        self.json_reply(404, {"error": {"code": "NotFound", "message": parsed.path}})

    def log_message(self, fmt, *args):
        pass  # keep the proof output clean


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", required=True, help="directory of <secret-name>.txt files")
    ap.add_argument("--port", type=int, default=18300)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    Handler.data_dir = os.path.abspath(args.data)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"keyvault-stub serving {Handler.data_dir} on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
