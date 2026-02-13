#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
import base64
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_DIR = os.path.dirname(__file__)
TOKENS_PATH = os.path.join(BASE_DIR, "tokens.json")
POLICIES_PATH = os.path.join(BASE_DIR, "policies.json")
CACHE_PATH = os.path.join(BASE_DIR, ".cv_authtoken_cache.json")
LOG_PATH = os.path.join(BASE_DIR, "commvault_jobs_by_client.log")

# Evita login a cada item (Zabbix chama em paralelo)
DEFAULT_TOKEN_TTL_SEC = 50 * 60          # 50 min
LOGIN_BACKOFF_SEC = 10 * 60              # se login falhar, espera 10 min antes de tentar de novo

ACTIVE_STATUS = {
    "running", "waiting", "pending", "queued", "active",
    "preparing", "starting", "in progress", "inprogress", "suspended"
}
FINAL_STATUS = {
    "completed", "completed w/ errors", "completed with errors", "failed",
    "killed", "canceled", "cancelled", "skipped", "success"
}

RESTORE_OPTYPES = {5}
BACKUP_OPTYPES = {4, 59}

DOW = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]  # 0=mon .. 6=sun


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    # mantém debug no stderr (Zabbix ignora stderr normalmente)
    print(line, file=sys.stderr)


def load_json_file(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception:
        return default


def save_json_atomic(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def load_tokens(path: str) -> dict:
    data = load_json_file(path, None)
    if not isinstance(data, dict):
        raise ValueError("tokens.json inválido (não é JSON dict)")

    for k in ("host", "username", "password"):
        v = data.get(k)
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"tokens.json: faltando '{k}' para login")

    data["host"] = data["host"].rstrip("/")
    return data


def load_policies(path: str) -> dict:
    data = load_json_file(path, {})
    return data if isinstance(data, dict) else {}


def build_verify_param(tokens: dict, args_verify_tls: bool, args_ca_bundle: str | None):
    if args_ca_bundle:
        return args_ca_bundle
    if args_verify_tls:
        return True

    ca = tokens.get("caBundle")
    if isinstance(ca, str) and ca.strip():
        return ca.strip()

    v = tokens.get("verifyTLS")
    if isinstance(v, bool) and v:
        return True

    return False


def current_day_key() -> str:
    return DOW[time.localtime().tm_wday]


def is_weekend() -> bool:
    return time.localtime().tm_wday >= 5


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


def get_allowed_window_for_client(client_name: str, policies: dict, fallback_window: str) -> str:
    client_name = (client_name or "").strip()
    day = current_day_key()
    wknd = is_weekend()

    default = policies.get("default", {}) if isinstance(policies, dict) else {}
    if not isinstance(default, dict):
        default = {}

    cpol = policies.get(client_name, {}) if isinstance(policies, dict) else {}
    if not isinstance(cpol, dict):
        cpol = {}

    days = cpol.get("days")
    if isinstance(days, dict):
        w = days.get(day)
        if isinstance(w, str) and w.strip():
            return w.strip()

    key = "weekend" if wknd else "weekday"
    w = cpol.get(key)
    if isinstance(w, str) and w.strip():
        return w.strip()

    w = default.get(key)
    if isinstance(w, str) and w.strip():
        return w.strip()

    return fallback_window


def api_get(host: str, authtoken: str, path: str, verify_param):
    url = f"{host}{path}"
    return requests.get(
        url,
        headers={"Accept": "application/json", "Authtoken": authtoken},
        timeout=30,
        verify=verify_param,
    )


def _cache_read() -> dict:
    d = load_json_file(CACHE_PATH, {})
    return d if isinstance(d, dict) else {}


def _cache_write(d: dict) -> None:
    save_json_atomic(CACHE_PATH, d)


def get_cached_authtoken(host: str) -> str | None:
    c = _cache_read()
    key = host
    ent = c.get(key)
    if not isinstance(ent, dict):
        return None
    tok = ent.get("authtoken")
    exp = ent.get("expiresAt", 0)
    if not isinstance(tok, str) or not tok.strip():
        return None
    try:
        exp = int(exp)
    except Exception:
        return None
    if time.time() >= exp:
        return None
    return tok.strip()


def set_cached_authtoken(host: str, authtoken: str, ttl_sec: int) -> None:
    c = _cache_read()
    c[host] = {"authtoken": authtoken, "expiresAt": int(time.time()) + int(ttl_sec)}
    _cache_write(c)


def get_login_backoff_until(host: str) -> int:
    c = _cache_read()
    ent = c.get(host)
    if not isinstance(ent, dict):
        return 0
    try:
        return int(ent.get("loginBackoffUntil", 0) or 0)
    except Exception:
        return 0


def set_login_backoff(host: str, seconds: int) -> None:
    c = _cache_read()
    ent = c.get(host)
    if not isinstance(ent, dict):
        ent = {}
    ent["loginBackoffUntil"] = int(time.time()) + int(seconds)
    c[host] = ent
    _cache_write(c)


def clear_login_backoff(host: str) -> None:
    c = _cache_read()
    ent = c.get(host)
    if isinstance(ent, dict) and "loginBackoffUntil" in ent:
        ent.pop("loginBackoffUntil", None)
        c[host] = ent
        _cache_write(c)


def commvault_login(tokens: dict, verify_param) -> str:
    host = tokens["host"]
    username = tokens["username"]
    password = tokens["password"]
    domain = tokens.get("domain", "") or ""
    commserver = tokens.get("commserver", "") or ""

    # evita “hammer” em caso de credencial errada / conta bloqueada
    backoff_until = get_login_backoff_until(host)
    if time.time() < backoff_until:
        raise RuntimeError(f"login em backoff até {time.strftime('%H:%M:%S', time.localtime(backoff_until))}")

    pw_b64 = base64.b64encode(password.encode("utf-8")).decode("ascii")

    # Endpoint que funcionou no seu teste: /commandcenter/api/Login
    url = f"{host}/commandcenter/api/Login"
    payload = {
        "username": username,
        "password": pw_b64,
        "domain": domain,
    }
    if commserver:
        payload["commserver"] = commserver

    r = requests.post(
        url,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
        verify=verify_param,
    )

    if r.status_code != 200:
        # aplica backoff para não travar conta
        set_login_backoff(host, LOGIN_BACKOFF_SEC)
        raise RuntimeError(f"Login HTTP {r.status_code}: {(r.text or '')[:200]}")

    try:
        j = r.json()
    except Exception:
        set_login_backoff(host, LOGIN_BACKOFF_SEC)
        raise RuntimeError("Login retornou 200 mas não é JSON")

    # Muitos ambientes retornam "token" (Authtoken) aqui
    autht = j.get("token") or j.get("authtoken") or j.get("authToken")
    if not isinstance(autht, str) or not autht.strip():
        # se veio erro estruturado
        set_login_backoff(host, LOGIN_BACKOFF_SEC)
        raise RuntimeError(f"Login sem token no JSON: {str(j)[:260]}")

    clear_login_backoff(host)
    return autht.strip()


def get_authtoken(tokens: dict, verify_param, ttl_sec: int, debug: bool) -> str:
    host = tokens["host"]
    cached = get_cached_authtoken(host)
    if cached:
        if debug:
            log(f"[debug] usando authtoken em cache")
        return cached

    autht = commvault_login(tokens, verify_param)
    set_cached_authtoken(host, autht, ttl_sec)
    if debug:
        log(f"[debug] novo authtoken obtido via login (cache TTL={ttl_sec}s)")
    return autht


def collect_dicts_with_key(obj, key: str):
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


def job_is_restore(job: dict) -> bool:
    op = job.get("opType")
    if isinstance(op, int) and op in RESTORE_OPTYPES:
        return True
    jt = (job.get("jobType") or "").strip().lower()
    if jt == "restore":
        return True
    lop = (job.get("localizedOperationName") or "").strip().lower()
    if lop == "restore":
        return True
    return False


def job_is_backup_only(job: dict) -> bool:
    if job_is_restore(job):
        return False
    op = job.get("opType")
    if isinstance(op, int) and op in BACKUP_OPTYPES:
        return True
    jt = (job.get("jobType") or "").strip().lower()
    lop = (job.get("localizedOperationName") or "").strip().lower()
    return ("backup" in jt) or ("backup" in lop)


def get_clients_visible(host: str, authtoken: str, verify_param):
    r = api_get(host, authtoken, "/commandcenter/api/Client?limit=5000", verify_param)
    if r.status_code != 200:
        return None, r
    data = r.json()
    clients = collect_dicts_with_key(data, "clientId")
    seen = {}
    for c in clients:
        cid = c.get("clientId")
        name = c.get("displayName") or c.get("clientName") or c.get("name")
        if cid and isinstance(name, str) and name.strip():
            seen[str(cid)] = name.strip()
    return seen, r


def get_jobs_payload(host: str, authtoken: str, verify_param, limit: int):
    paths = [
        f"/commandcenter/api/Job?jobCategory=Active&jobFilter=backup&limit={limit}",
        f"/commandcenter/api/Job?jobCategory=Active&limit={limit}",
        f"/commandcenter/api/Job?status=Running&limit={limit}",
        f"/commandcenter/api/Job?limit={limit}",
    ]

    last = None
    for path in paths:
        r = api_get(host, authtoken, path, verify_param)
        last = (path, r)

        if r.status_code == 200:
            try:
                jobs = collect_jobs(r.json())
            except Exception:
                return None, r, path
            jobs_active = [j for j in jobs if job_is_active(j)]
            return jobs_active, r, path

        if r.status_code in (400, 404):
            continue

        if r.status_code in (401, 403):
            return None, r, path

        return None, r, path

    if last:
        return None, last[1], last[0]
    return None, None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--discover", action="store_true", help="Retorna JSON LLD com clients visíveis")
    ap.add_argument("--client", default=None, help="Nome do client para contagem de jobs ativos fora da janela")
    ap.add_argument("--limit", type=int, default=200)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--allowed-window", default=None, help="Fallback HH:MM-HH:MM (se não houver policy). Ex.: 18:00-05:45")
    ap.add_argument("--verify-tls", action="store_true", help="Força verify=True (usa trust store do sistema)")
    ap.add_argument("--ca-bundle", default=None, help="Caminho para CA bundle .crt/.pem (verify=<path>)")
    ap.add_argument("--token-ttl", type=int, default=DEFAULT_TOKEN_TTL_SEC, help="TTL do Authtoken em cache (segundos)")
    args = ap.parse_args()

    fallback_window = args.allowed_window.strip() if isinstance(args.allowed_window, str) and args.allowed_window.strip() else "18:00-05:45"

    # tokens/policies
    try:
        tokens = load_tokens(TOKENS_PATH)
    except Exception as ex:
        # discovery: sempre JSON
        if args.discover:
            log(f"[Commvault] discovery falhou: {ex}")
            print(json.dumps({"data": []}))
        else:
            log(f"[Commvault] jobs falhou: {ex}")
            print("0")
        return

    policies = load_policies(POLICIES_PATH)
    verify_param = build_verify_param(tokens, args.verify_tls, args.ca_bundle)

    host = tokens["host"]

    if args.debug:
        log(f"[debug] verify={verify_param} host={host}")

    # ---------------- DISCOVERY ----------------
    if args.discover:
        try:
            authtoken = get_authtoken(tokens, verify_param, args.token_ttl, args.debug)
            clients, resp = get_clients_visible(host, authtoken, verify_param)

            # Se token expirou/revogado: tenta 1x novo login
            if resp is not None and resp.status_code in (401, 403):
                if args.debug:
                    log("[auth] 401/403 em discovery -> refazendo login")
                set_cached_authtoken(host, "", 0)  # invalida cache
                authtoken = commvault_login(tokens, verify_param)
                set_cached_authtoken(host, authtoken, args.token_ttl)
                clients, resp = get_clients_visible(host, authtoken, verify_param)

            if resp is None or resp.status_code != 200 or clients is None:
                log(f"[Commvault] discovery falhou HTTP {None if resp is None else resp.status_code}: {(resp.text or '')[:160] if resp else ''}")
                print(json.dumps({"data": []}))
                return

            data = [{"{#CLIENT}": name} for _, name in sorted(clients.items(), key=lambda x: x[1])]
            print(json.dumps({"data": data}))
            return

        except Exception as ex:
            log(f"[Commvault] discovery exceção: {ex}")
            print(json.dumps({"data": []}))
            return

    # ---------------- JOBS POR CLIENT ----------------
    if not args.client:
        print("0")
        return

    client_name = args.client.strip()
    window = get_allowed_window_for_client(client_name, policies, fallback_window)

    if args.debug:
        log(f"[policy] client={client_name} day={current_day_key()} weekend={is_weekend()} window={window}")

    # Dentro da janela => não alertar
    try:
        if is_now_in_window(window):
            print("0")
            return
    except Exception as ex:
        log(f"[Commvault] janela inválida '{window}': {ex}")
        print("0")
        return

    try:
        authtoken = get_authtoken(tokens, verify_param, args.token_ttl, args.debug)
        jobs, resp, path_used = get_jobs_payload(host, authtoken, verify_param, args.limit)

        # token expirou/revogado -> tenta 1x login novo e refaz
        if resp is not None and resp.status_code in (401, 403):
            if args.debug:
                log("[auth] 401/403 em jobs -> refazendo login")
            set_cached_authtoken(host, "", 0)
            authtoken = commvault_login(tokens, verify_param)
            set_cached_authtoken(host, authtoken, args.token_ttl)
            jobs, resp, path_used = get_jobs_payload(host, authtoken, verify_param, args.limit)

        if args.debug and path_used and resp is not None:
            log(f"[debug] url_used={host}{path_used} http={resp.status_code}")

        if resp is None or resp.status_code != 200 or jobs is None:
            log(f"[Commvault] jobs falhou HTTP {None if resp is None else resp.status_code}: {(resp.text or '')[:160] if resp else ''}")
            print("0")
            return

        target = client_name.lower()
        cnt = 0
        for j in jobs:
            if not job_is_backup_only(j):
                continue
            dc = j.get("destClientName")
            if isinstance(dc, str) and dc.strip().lower() == target:
                cnt += 1

        print(str(cnt))
        return

    except Exception as ex:
        log(f"[Commvault] jobs exceção: {ex}")
        print("0")
        return


if __name__ == "__main__":
    main()
