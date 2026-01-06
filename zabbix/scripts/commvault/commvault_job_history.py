#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_DIR = os.path.dirname(__file__)
TOKENS_PATH = os.path.join(BASE_DIR, "tokens.json")
RENEW_LOCK_PATH = "/tmp/commvault_token_renew.lock"

FINAL_STATUS = {
    "completed", "completed w/ errors", "completed with errors", "failed",
    "killed", "canceled", "cancelled", "skipped", "success"
}

ACTIVE_STATUS = {
    "running", "waiting", "pending", "queued", "active",
    "preparing", "starting", "in progress", "inprogress", "suspended"
}


def eprint(msg: str):
    print(msg, file=sys.stderr)


def load_tokens(path: str) -> dict:
    with open(path, "r") as f:
        t = json.load(f)
    for k in ("host", "accessToken", "refreshToken"):
        if not isinstance(t.get(k), str) or not t[k].strip():
            raise ValueError(f"tokens.json inválido: faltando '{k}'")
    t["host"] = t["host"].rstrip("/")
    return t


def save_json_atomic(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def build_verify_param(tokens: dict, verify_tls: bool, ca_bundle: str | None):
    if ca_bundle:
        return ca_bundle
    if verify_tls:
        return True
    ca = tokens.get("caBundle")
    if isinstance(ca, str) and ca.strip():
        return ca.strip()
    v = tokens.get("verifyTLS")
    if isinstance(v, bool) and v:
        return True
    return False


def api_get(host: str, access: str, path: str, verify_param):
    url = f"{host}{path}"
    return requests.get(
        url,
        headers={"Accept": "application/json", "Authorization": f"Bearer {access}"},
        timeout=30,
        verify=verify_param,
    )


def api_post(host: str, access: str, path: str, payload: dict, verify_param, with_auth: bool):
    url = f"{host}{path}"
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if with_auth:
        headers["Authorization"] = f"Bearer {access}"
    return requests.post(url, headers=headers, json=payload, timeout=30, verify=verify_param)


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


def renew_tokens(host: str, access: str, refresh: str, verify_param):
    candidates = [
        "/commandcenter/api/V4/AccessToken/Renew",
        "/commandcenter/api/V4/AccessToken/renew",
        "/webconsole/api/V4/AccessToken/Renew",
        "/webconsole/api/V4/AccessToken/renew",
    ]
    payload = {"accessToken": access, "refreshToken": refresh}

    last_err = None
    for path in candidates:
        for mode in ("with_auth", "no_auth"):
            with_auth = (mode == "with_auth")
            try:
                r = api_post(host, access, path, payload, verify_param, with_auth=with_auth)
            except Exception as ex:
                last_err = f"{host}{path} ({mode}) -> EXC {ex}"
                continue

            if r.status_code == 200:
                try:
                    j = r.json()
                except Exception:
                    last_err = f"{host}{path} ({mode}) -> 200 mas não é JSON"
                    continue

                new_a, new_r = _extract_new_tokens(j)
                if new_a and new_r:
                    return new_a, new_r
                last_err = f"{host}{path} ({mode}) -> 200 mas sem access/refresh"
                continue

            if r.status_code == 404:
                last_err = f"{host}{path} ({mode}) -> 404"
                continue

            body = (r.text or "")[:200].replace("\n", " ")
            last_err = f"{host}{path} ({mode}) -> {r.status_code} {body}"

    raise RuntimeError(f"Falha ao renovar token. Último erro: {last_err}")


def with_renew_lock(func):
    def wrapper(*args, **kwargs):
        try:
            import fcntl
        except Exception:
            return func(*args, **kwargs)

        fd = None
        try:
            fd = open(RENEW_LOCK_PATH, "w")
            fcntl.flock(fd, fcntl.LOCK_EX)
            return func(*args, **kwargs)
        finally:
            try:
                if fd:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    fd.close()
            except Exception:
                pass
    return wrapper


@with_renew_lock
def safe_renew_and_update(tokens: dict, verify_param):
    host = tokens["host"]
    access = tokens["accessToken"]
    refresh = tokens["refreshToken"]
    new_a, new_r = renew_tokens(host, access, refresh, verify_param)
    tokens["accessToken"] = new_a
    tokens["refreshToken"] = new_r
    save_json_atomic(TOKENS_PATH, tokens)
    return new_a, new_r


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
    endt = job.get("jobEndTime")
    if endt in (None, 0, "0", "") and job.get("jobStartTime") not in (None, 0, "0", ""):
        return True
    return False


def parse_since(s: str) -> int:
    """
    Aceita: 24h, 7d, 30m
    Retorna epoch seconds limite (agora - delta)
    """
    s = s.strip().lower()
    if s.endswith("h"):
        n = int(s[:-1]); delta = n * 3600
    elif s.endswith("d"):
        n = int(s[:-1]); delta = n * 86400
    elif s.endswith("m"):
        n = int(s[:-1]); delta = n * 60
    else:
        raise ValueError("Use formato tipo 24h, 7d, 30m")
    return int(time.time()) - delta


def to_iso(epoch_s) -> str:
    try:
        if epoch_s in (None, 0, "0", ""):
            return "-"
        epoch_s = int(epoch_s)
        return datetime.fromtimestamp(epoch_s).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


def fetch_jobs(host: str, access: str, verify_param, limit: int, debug: bool):
    # tenta ordenar (varia por versão). Se falhar, cai no básico.
    paths = [
        f"/commandcenter/api/Job?limit={limit}&orderBy=jobEndTime%20desc",
        f"/commandcenter/api/Job?limit={limit}&sort=jobEndTime:desc",
        f"/commandcenter/api/Job?limit={limit}",
    ]
    last = None
    for p in paths:
        r = api_get(host, access, p, verify_param)
        last = (p, r)
        if debug:
            eprint(f"[fetch] {host}{p} -> {r.status_code}")
        if r.status_code == 200:
            jobs = collect_jobs(r.json())
            return jobs, r, p
        if r.status_code in (400, 404):
            continue
        return None, r, p
    if last:
        return None, last[1], last[0]
    return None, None, ""


def main():
    ap = argparse.ArgumentParser(description="Commvault Job History lister (Command Center API)")
    ap.add_argument("--limit", type=int, default=500, help="Qtde máxima de jobs trazidos da API")
    ap.add_argument("--since", default="24h", help="Período (ex.: 24h, 7d, 30m)")
    ap.add_argument("--client", default=None, help="Filtra por destClientName (ex.: S154FJDF0001)")
    ap.add_argument("--status", default=None, help="Filtra por status (case-insensitive). Ex.: Completed, Failed, Killed")
    ap.add_argument("--active-only", action="store_true", help="Mostra apenas jobs ativos (heurística local)")
    ap.add_argument("--json", action="store_true", help="Saída em JSON (ao invés de tabela)")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--ca-bundle", default=None)
    args = ap.parse_args()

    tokens = load_tokens(TOKENS_PATH)
    verify_param = build_verify_param(tokens, args.verify_tls, args.ca_bundle)

    host = tokens["host"]
    access = tokens["accessToken"]

    since_epoch = parse_since(args.since)

    jobs, resp, path_used = fetch_jobs(host, access, verify_param, args.limit, args.debug)

    # renew se precisar
    if resp is not None and resp.status_code in (401, 403):
        if args.debug:
            eprint("[auth] 401/403 -> tentando renew")
        new_a, _ = safe_renew_and_update(tokens, verify_param)
        access = new_a
        jobs, resp, path_used = fetch_jobs(host, access, verify_param, args.limit, args.debug)

    if resp is None or resp.status_code != 200 or jobs is None:
        eprint(f"[erro] Falha ao buscar jobs: HTTP={None if resp is None else resp.status_code} path={path_used}")
        sys.exit(2)

    # filtros locais
    out = []
    client_f = args.client.strip().lower() if args.client else None
    status_f = args.status.strip().lower() if args.status else None

    for j in jobs:
        # período: usa endTime se existir, senão startTime, senão ignora
        jt = j.get("jobEndTime") or j.get("completedTime") or j.get("jobStartTime") or 0
        try:
            jt = int(jt)
        except Exception:
            jt = 0
        if jt and jt < since_epoch:
            continue

        if args.active_only and not job_is_active(j):
            continue

        if client_f:
            dc = j.get("destClientName") or ""
            if not (isinstance(dc, str) and dc.strip().lower() == client_f):
                continue

        if status_f:
            st = (j.get("status") or j.get("localizedStatus") or "")
            if not (isinstance(st, str) and st.strip().lower() == status_f):
                continue

        out.append(j)

    if args.json:
        # reduz campos principais pra ficar legível
        slim = []
        for j in out:
            slim.append({
                "jobId": j.get("jobId"),
                "status": j.get("status") or j.get("localizedStatus"),
                "destClientName": j.get("destClientName"),
                "subclientName": j.get("subclientName"),
                "jobStartTime": j.get("jobStartTime"),
                "jobEndTime": j.get("jobEndTime"),
                "jobStartISO": to_iso(j.get("jobStartTime")),
                "jobEndISO": to_iso(j.get("jobEndTime")),
                "percentComplete": j.get("percentComplete"),
                "currentPhaseName": j.get("currentPhaseName"),
            })
        print(json.dumps(slim, indent=2))
        return

    # tabela simples
    print(f"BASE={host}")
    print(f"QUERY={host}{path_used}")
    print(f"since={args.since} ({to_iso(since_epoch)})  limit={args.limit}  matched={len(out)}")
    print("-" * 120)
    print(f"{'jobId':>8}  {'status':<12}  {'client':<18}  {'subclient':<20}  {'start':<19}  {'end':<19}  {'%':>3}")
    print("-" * 120)

    for j in out[:1000]:
        job_id = str(j.get("jobId") or "-")
        st = (j.get("status") or j.get("localizedStatus") or "-")
        client = (j.get("destClientName") or "-")
        subc = (j.get("subclientName") or "-")
        stt = to_iso(j.get("jobStartTime"))
        end = to_iso(j.get("jobEndTime"))
        pct = str(j.get("percentComplete") or "-")
        print(f"{job_id:>8}  {st:<12.12}  {client:<18.18}  {subc:<20.20}  {stt:<19}  {end:<19}  {pct:>3}")

    if len(out) > 1000:
        print(f"... (mostrando 1000 de {len(out)})")


if __name__ == "__main__":
    main()
