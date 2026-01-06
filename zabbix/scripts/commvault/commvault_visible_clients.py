#!/usr/bin/env python3
import json
import os
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TOKENS_PATH = os.path.join(os.path.dirname(__file__), "tokens.json")
VERIFY_TLS = False

def load_tokens(path: str) -> dict:
    with open(path, "r") as f:
        data = json.load(f)
    for k in ("host", "accessToken", "refreshToken"):
        if k not in data or not isinstance(data[k], str) or not data[k].strip():
            raise ValueError(f"tokens.json inválido: faltando '{k}'")
    data["host"] = data["host"].rstrip("/")
    return data

def save_tokens(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def _extract_new_tokens(resp_json: dict):
    if isinstance(resp_json, dict):
        a = resp_json.get("accessToken")
        r = resp_json.get("refreshToken")
        if isinstance(a, str) and isinstance(r, str) and a and r:
            return a, r
        for k in ("tokenInfo", "data", "response"):
            v = resp_json.get(k)
            if isinstance(v, dict):
                a = v.get("accessToken")
                r = v.get("refreshToken")
                if isinstance(a, str) and isinstance(r, str) and a and r:
                    return a, r
    return None, None

def renew_tokens(host: str, access: str, refresh: str):
    candidates = [
        f"{host}/commandcenter/api/V4/AccessToken/Renew",
        f"{host}/commandcenter/api/V4/AccessToken/renew",
        f"{host}/webconsole/api/V4/AccessToken/Renew",
        f"{host}/webconsole/api/V4/AccessToken/renew",
    ]

    payload = {"accessToken": access, "refreshToken": refresh}
    headers_base = {"Accept": "application/json", "Content-Type": "application/json"}

    last_err = None
    for url in candidates:
        for mode in ("with_auth", "no_auth"):
            headers = dict(headers_base)
            if mode == "with_auth":
                headers["Authorization"] = f"Bearer {access}"

            try:
                r = requests.post(url, headers=headers, json=payload, timeout=30, verify=VERIFY_TLS)
            except Exception as e:
                last_err = f"{url} ({mode}) -> EXC {e}"
                continue

            if r.status_code == 200:
                try:
                    j = r.json()
                except Exception:
                    last_err = f"{url} ({mode}) -> 200 mas não é JSON"
                    continue

                new_a, new_r = _extract_new_tokens(j)
                if new_a and new_r:
                    return new_a, new_r

                last_err = f"{url} ({mode}) -> 200 mas sem access/refresh no JSON"
                continue

            if r.status_code == 404:
                last_err = f"{url} ({mode}) -> 404"
                continue

            last_err = f"{url} ({mode}) -> {r.status_code} {r.text[:200]}"

    raise RuntimeError(f"Falha ao renovar token. Último erro: {last_err}")

def get_json(host, token, path):
    url = f"{host}{path}"
    r = requests.get(
        url,
        headers={"Accept":"application/json", "Authorization": f"Bearer {token}"},
        timeout=30,
        verify=VERIFY_TLS
    )
    return r

def collect_dicts_with_key(obj, key):
    out = []
    if isinstance(obj, dict):
        if key in obj:
            out.append(obj)
        for v in obj.values():
            out.extend(collect_dicts_with_key(v, key))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(collect_dicts_with_key(it, key))
    return out

def main():
    t = load_tokens(TOKENS_PATH)
    host = t["host"]
    access = t["accessToken"]
    refresh = t["refreshToken"]

    # Endpoint de clients (Command Center)
    path = "/commandcenter/api/Client?limit=5000"

    r = get_json(host, access, path)

    # Se expirou (401/403), renova e tenta de novo
    if r.status_code in (401, 403):
        new_access, new_refresh = renew_tokens(host, access, refresh)
        t["accessToken"] = new_access
        t["refreshToken"] = new_refresh
        save_tokens(TOKENS_PATH, t)
        access = new_access
        r = get_json(host, access, path)

    print("HTTP", r.status_code)
    if r.status_code != 200:
        print(r.text[:400])
        print("\nSe continuar 401/403: refresh token expirou/renewable_until passou OU RBAC bloqueou.")
        sys.exit(2)

    data = r.json()
    clients = collect_dicts_with_key(data, "clientId")

    seen = {}
    for c in clients:
        cid = c.get("clientId")
        name = c.get("displayName") or c.get("clientName") or c.get("name")
        if cid and name:
            seen[cid] = name

    print(f"Clients visíveis: {len(seen)}\n")
    for cid, name in sorted(seen.items(), key=lambda x: x[1]):
        print(f"- {name} (clientId={cid})")

if __name__ == "__main__":
    main()
