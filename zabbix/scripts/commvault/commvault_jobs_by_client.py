#!/usr/bin/env python3
import json
import os
import sys
import time
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

TOKENS_PATH = os.path.join(os.path.dirname(__file__), "tokens.json")
VERIFY_TLS = False

ACTIVE_STATUS = {
    "running", "waiting", "pending", "queued", "active",
    "preparing", "starting", "in progress", "inprogress", "suspended"
}
FINAL_STATUS = {
    "completed", "completed w/ errors", "completed with errors", "failed",
    "killed", "canceled", "cancelled", "skipped", "success"
}

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
                last_err = f"{url} ({mode}) -> 200 mas sem tokens no JSON"
                continue

            if r.status_code == 404:
                last_err = f"{url} ({mode}) -> 404"
                continue

            last_err = f"{url} ({mode}) -> {r.status_code} {r.text[:200]}"

    raise RuntimeError(f"Falha ao renovar token. Último erro: {last_err}")

def api_get(host: str, access: str, path: str):
    url = f"{host}{path}"
    return requests.get(
        url,
        headers={"Accept":"application/json", "Authorization": f"Bearer {access}"},
        timeout=30,
        verify=VERIFY_TLS
    )

def collect_jobs(obj):
    out = []
    if isinstance(obj, dict):
        if "jobId" in obj:
            out.append(obj)
        for v in obj.values():
            out.extend(collect_jobs(v))
    elif isinstance(obj, list):
        for it in obj:
            out.extend(collect_jobs(it))
    return out

def norm_status(job: dict) -> str:
    for k in ("status", "localizedStatus", "currentPhaseName"):
        v = job.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    return ""

def job_is_active(job: dict) -> bool:
    st = norm_status(job)
    if st in FINAL_STATUS:
        return False
    if st in ACTIVE_STATUS:
        return True

    # heurística: jobEndTime vazio/0 => ainda ativo
    endt = job.get("jobEndTime")
    if endt in (None, 0, "0", "") and job.get("jobStartTime") not in (None, 0, "0", ""):
        return True
    return False

def parse_allowed_window(window: str):
    a, b = window.split("-", 1)
    sh, sm = map(int, a.split(":"))
    eh, em = map(int, b.split(":"))
    return sh * 60 + sm, eh * 60 + em

def is_now_in_window(window: str) -> bool:
    start, end = parse_allowed_window(window)
    now = time.localtime()
    cur = now.tm_hour * 60 + now.tm_min
    if start <= end:
        return start <= cur < end
    return cur >= start or cur < end

def get_clients_visible(host, access):
    r = api_get(host, access, "/commandcenter/api/Client?limit=5000")
    if r.status_code != 200:
        return r.status_code, None, r.text
    data = r.json()

    # pega dicts que parecem clients
    clients = []
    def walk(o):
        if isinstance(o, dict):
            if "clientId" in o:
                clients.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for it in o:
                walk(it)
    walk(data)

    seen = {}
    for c in clients:
        cid = c.get("clientId")
        name = c.get("displayName") or c.get("clientName") or c.get("name")
        if cid and name:
            seen[str(cid)] = name
    return 200, seen, ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--discover", action="store_true", help="Saída LLD JSON de clients visíveis")
    ap.add_argument("--client", default=None, help="Nome do client para retornar count de jobs ativos fora da janela")
    ap.add_argument("--allowed-window", default="00:00-05:45", help="HH:MM-HH:MM (dentro retorna 0)")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args()

    t = load_tokens(TOKENS_PATH)
    host = t["host"]
    access = t["accessToken"]
    refresh = t["refreshToken"]

    # --- DISCOVERY ---
    if args.discover:
        r = api_get(host, access, "/commandcenter/api/Client?limit=5000")
        if r.status_code in (401, 403):
            new_a, new_r = renew_tokens(host, access, refresh)
            t["accessToken"], t["refreshToken"] = new_a, new_r
            save_tokens(TOKENS_PATH, t)
            access = new_a
            r = api_get(host, access, "/commandcenter/api/Client?limit=5000")

        if r.status_code != 200:
            # se discovery falhar, devolve vazio (não quebra o template)
            print(json.dumps({"data": []}))
            return

        code, seen, _ = get_clients_visible(host, access)
        data = [{"{#CLIENT}": name} for _, name in sorted(seen.items(), key=lambda x: x[1])]
        print(json.dumps({"data": data}))
        return

    # --- COUNT POR CLIENT ---
    if not args.client:
        print("0")
        return

    # dentro da janela permitida => não alertar
    if is_now_in_window(args.allowed_window):
        print("0")
        return

    # pega jobs (tenta Running)
    path = f"/commandcenter/api/Job?status=Running&limit={args.limit}"
    r = api_get(host, access, path)

    if r.status_code in (401, 403):
        new_a, new_r = renew_tokens(host, access, refresh)
        t["accessToken"], t["refreshToken"] = new_a, new_r
        save_tokens(TOKENS_PATH, t)
        access = new_a
        r = api_get(host, access, path)

    if r.status_code != 200:
        print("0")
        return

    jobs = collect_jobs(r.json())
    client_name = args.client.strip().lower()

    cnt = 0
    for j in jobs:
        dc = j.get("destClientName")
        if isinstance(dc, str) and dc.strip().lower() == client_name:
            if job_is_active(j):
                cnt += 1

    print(str(cnt))

if __name__ == "__main__":
    main()