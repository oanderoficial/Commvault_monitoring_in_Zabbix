#!/usr/bin/env python3
import json
import os
import sys
import time
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

DEFAULT_TOKENS_PATH = os.path.join(os.path.dirname(__file__), "tokens.json")

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

def renew_tokens(host: str, access: str, refresh: str, verify_tls: bool):
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
                r = requests.post(url, headers=headers, json=payload, timeout=30, verify=verify_tls)
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

def api_get(url: str, access: str, verify_tls: bool):
    headers = {"Accept": "application/json", "Authorization": f"Bearer {access}"}
    return requests.get(url, headers=headers, timeout=30, verify=verify_tls)

def collect_job_dicts(obj):
    jobs = []
    if isinstance(obj, dict):
        if "jobId" in obj:
            jobs.append(obj)
        for v in obj.values():
            jobs.extend(collect_job_dicts(v))
    elif isinstance(obj, list):
        for it in obj:
            jobs.extend(collect_job_dicts(it))
    return jobs

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

    # heurística: jobEndTime ausente/0 => ativo
    endt = job.get("jobEndTime")
    if endt in (None, 0, "0", "") and job.get("jobStartTime") not in (None, 0, "0", ""):
        return True

    # percentComplete < 100 e sem end
    pc = job.get("percentComplete")
    try:
        if pc is not None and float(pc) < 100 and endt in (None, 0, "0", ""):
            return True
    except Exception:
        pass

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

def get_jobs_payload(host: str, access: str, verify_tls: bool, limit: int):
    # tenta “ativos” via query primeiro
    urls = [
        f"{host}/commandcenter/api/Job?status=Running&limit={limit}",
        f"{host}/commandcenter/api/Job?status=Active&limit={limit}",
        f"{host}/commandcenter/api/Job?status=running&limit={limit}",
        f"{host}/commandcenter/api/Job?limit={limit}",
    ]
    last = None
    for url in urls:
        r = api_get(url, access, verify_tls)
        last = (url, r)
        if r.status_code == 200:
            return url, r
        # se 400/404 pode ser parâmetro não suportado, tenta o próximo
        if r.status_code in (400, 404):
            continue
        # 401/403 será tratado fora (renew)
        if r.status_code in (401, 403):
            return url, r
    return last

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tokens", default=DEFAULT_TOKENS_PATH)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--allowed-window", default=None, help="HH:MM-HH:MM (se dentro, imprime 0)")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    t = load_tokens(args.tokens)
    host, access, refresh = t["host"], t["accessToken"], t["refreshToken"]

    if args.allowed_window and is_now_in_window(args.allowed_window):
        print("0")
        return

    url_used, r = get_jobs_payload(host, access, args.verify_tls, args.limit)

    if r.status_code in (401, 403):
        new_access, new_refresh = renew_tokens(host, access, refresh, args.verify_tls)
        t["accessToken"], t["refreshToken"] = new_access, new_refresh
        save_tokens(args.tokens, t)
        access = new_access
        url_used, r = get_jobs_payload(host, access, args.verify_tls, args.limit)

    if r.status_code != 200:
        print(f"ERRO GET jobs ({url_used}): {r.status_code} {r.text[:200]}", file=sys.stderr)
        sys.exit(2)

    data = r.json()
    jobs = collect_job_dicts(data)

    # Se o endpoint já devolveu só running/active, o filtro abaixo ainda é seguro
    active = [j for j in jobs if job_is_active(j)]

    if args.debug:
        print(f"url_used={url_used}", file=sys.stderr)
        print(f"jobs_total={len(jobs)} jobs_ativos={len(active)}", file=sys.stderr)
        if jobs:
            j0 = jobs[0]
            for k in ("jobId","status","localizedStatus","jobStartTime","jobEndTime","percentComplete","currentPhaseName","destClientName","subclientName"):
                if k in j0:
                    print(f"  {k}={j0.get(k)}", file=sys.stderr)
        for j in active[:10]:
            print(f"- jobId={j.get('jobId')} status={j.get('status')} end={j.get('jobEndTime')} client={j.get('destClientName')} subclient={j.get('subclientName')}", file=sys.stderr)

    print(len(active))

if __name__ == "__main__":
    main()
