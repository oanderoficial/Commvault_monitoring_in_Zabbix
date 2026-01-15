#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import sys
import time
import requests
from urllib3.exceptions import InsecureRequestWarning

# Evita warning quando verify=False
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_DIR = os.path.dirname(__file__)
TOKENS_PATH = os.path.join(BASE_DIR, "tokens.json")
POLICIES_PATH = os.path.join(BASE_DIR, "policies.json")
#RENEW_LOCK_PATH = "/tmp/commvault_token_renew.lock"
RENEW_LOCK_PATH = os.path.join(BASE_DIR, ".commvault_token_renew.lock")

# Status "ativos" (fallback caso endpoint filtrado não funcione)
ACTIVE_STATUS = {
    "running", "waiting", "pending", "queued", "active",
    "preparing", "starting", "in progress", "inprogress", "suspended"
}
FINAL_STATUS = {
    "completed", "completed w/ errors", "completed with errors", "failed",
    "killed", "canceled", "cancelled", "skipped", "success"
}

# ---- Job type filtering (simplificado) ----
# Pelo seu JSON:
# - Restore:  opType=5,  jobType="Restore", localizedOperationName="Restore"
# - Backup:   opType=59, jobType="Snap Backup", localizedOperationName="Snap Backup"
RESTORE_OPTYPES = {5}
BACKUP_OPTYPES = {4, 59}

DOW = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]  # 0=mon .. 6=sun


def eprint(msg: str):
    print(msg, file=sys.stderr)


def load_json_file(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception:
        return default


def save_json_atomic(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_tokens(path: str) -> dict:
    data = load_json_file(path, None)
    if not isinstance(data, dict):
        raise ValueError("tokens.json inválido (não é JSON dict)")

    for k in ("host", "accessToken", "refreshToken"):
        v = data.get(k)
        if not isinstance(v, str) or not v.strip():
            raise ValueError(f"tokens.json inválido: faltando '{k}'")
    data["host"] = data["host"].rstrip("/")
    return data


def load_policies(path: str) -> dict:
    data = load_json_file(path, {})
    return data if isinstance(data, dict) else {}


def current_day_key() -> str:
    return DOW[time.localtime().tm_wday]


def is_weekend() -> bool:
    return time.localtime().tm_wday >= 5  # sat/sun


def parse_allowed_window(window: str):
    """
    window: "HH:MM-HH:MM"
    Retorna (start_min, end_min) em minutos (0..1439)
    """
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
    # cruza meia-noite: permitido se >= start OU < end
    return cur >= start or cur < end


def get_allowed_window_for_client(client_name: str, policies: dict, fallback_window: str) -> str:
    """
    Prioridade:
      1) policies[CLIENT].days[mon..sun]
      2) policies[CLIENT].weekday/weekend
      3) policies.default.weekday/weekend
      4) fallback_window
    """
    client_name = (client_name or "").strip()
    day = current_day_key()
    wknd = is_weekend()

    default = policies.get("default", {}) if isinstance(policies, dict) else {}
    if not isinstance(default, dict):
        default = {}

    cpol = policies.get(client_name, {}) if isinstance(policies, dict) else {}
    if not isinstance(cpol, dict):
        cpol = {}

    # 1) days
    days = cpol.get("days")
    if isinstance(days, dict):
        w = days.get(day)
        if isinstance(w, str) and w.strip():
            return w.strip()

    # 2) weekday/weekend do client
    key = "weekend" if wknd else "weekday"
    w = cpol.get(key)
    if isinstance(w, str) and w.strip():
        return w.strip()

    # 3) default
    w = default.get(key)
    if isinstance(w, str) and w.strip():
        return w.strip()

    # 4) fallback
    return fallback_window


def build_verify_param(tokens: dict, args_verify_tls: bool, args_ca_bundle: str | None):
    """
    Regra:
      - se args_ca_bundle -> verify=<path>
      - senão se args_verify_tls -> verify=True
      - senão se tokens.caBundle -> verify=<path>
      - senão se tokens.verifyTLS==true -> verify=True
      - senão -> verify=False (compat)
    """
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

                last_err = f"{host}{path} ({mode}) -> 200 mas sem access/refresh no JSON"
                continue

            if r.status_code == 404:
                last_err = f"{host}{path} ({mode}) -> 404"
                continue

            body = (r.text or "")[:200].replace("\n", " ")
            last_err = f"{host}{path} ({mode}) -> {r.status_code} {body}"

    raise RuntimeError(f"Falha ao renovar token. Último erro: {last_err}")


def with_renew_lock(func):
    """
    Decorator simples pra evitar renew concorrente (Zabbix chama vários itens em paralelo).
    Usa lockfile com fcntl quando disponível (Linux).
    """
    def wrapper(*args, **kwargs):
        try:
            import fcntl  # Linux/Unix
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
    """
    Renova token e persiste em tokens.json (atomic).
    Retorna (new_access, new_refresh)
    """
    host = tokens["host"]
    access = tokens["accessToken"]
    refresh = tokens["refreshToken"]

    new_a, new_r = renew_tokens(host, access, refresh, verify_param)
    tokens["accessToken"] = new_a
    tokens["refreshToken"] = new_r
    save_json_atomic(TOKENS_PATH, tokens)
    return new_a, new_r


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

    # heurística: sem endTime => ainda ativo
    endt = job.get("jobEndTime")
    if endt in (None, 0, "0", "") and job.get("jobStartTime") not in (None, 0, "0", ""):
        return True

    return False


def job_type_blob(job: dict) -> str:
    jt = (job.get("jobType") or "").strip()
    lop = (job.get("localizedOperationName") or "").strip()
    op = job.get("opType")
    return f"jobType={jt} localizedOperationName={lop} opType={op}"


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
    # Nunca contar restore
    if job_is_restore(job):
        return False

    op = job.get("opType")
    if isinstance(op, int) and op in BACKUP_OPTYPES:
        return True

    # Fallback: conta qualquer operação com "backup"
    jt = (job.get("jobType") or "").strip().lower()
    lop = (job.get("localizedOperationName") or "").strip().lower()
    return ("backup" in jt) or ("backup" in lop)


def get_clients_visible(host: str, access: str, verify_param):
    """
    Retorna dict clientId(str) -> displayName(str)
    """
    r = api_get(host, access, "/commandcenter/api/Client?limit=5000", verify_param)
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


def get_jobs_payload(host: str, access: str, verify_param, limit: int):
    """
    Busca jobs preferindo filtros "ativos" por query.
    Retorna (jobs_ativos_filtrados_localmente, resp, path_usado).
    Observação: mesmo quando a API não filtra, SEMPRE filtramos localmente com job_is_active().
    """
    paths = [
        # Preferência: pedir só BACKUP direto na API (quando suportado)
        f"/commandcenter/api/Job?jobCategory=Active&jobFilter=backup&limit={limit}",
        f"/commandcenter/api/Job?jobCategory=ACTIVE&jobFilter=backup&limit={limit}",
        f"/commandcenter/api/Job?status=Running&jobFilter=backup&limit={limit}",
        f"/commandcenter/api/Job?status=Active&jobFilter=backup&limit={limit}",

        # Fallbacks (sem jobFilter)
        f"/commandcenter/api/Job?jobCategory=Active&limit={limit}",
        f"/commandcenter/api/Job?jobCategory=ACTIVE&limit={limit}",
        f"/commandcenter/api/Job?status=Running&limit={limit}",
        f"/commandcenter/api/Job?status=Active&limit={limit}",
        f"/commandcenter/api/Job?status=running&limit={limit}",
        f"/commandcenter/api/Job?limit={limit}",
    ]

    last = None
    for path in paths:
        r = api_get(host, access, path, verify_param)
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

    args = ap.parse_args()

    fallback_window = args.allowed_window.strip() if isinstance(args.allowed_window, str) and args.allowed_window.strip() else "18:00-05:45"

    try:
        tokens = load_tokens(TOKENS_PATH)
    except Exception as ex:
        eprint(f"[Commvault] erro tokens.json: {ex}")
        if args.discover:
            print(json.dumps({"data": []}))
        else:
            print("0")
        return

    policies = load_policies(POLICIES_PATH)
    verify_param = build_verify_param(tokens, args.verify_tls, args.ca_bundle)

    host = tokens["host"]
    access = tokens["accessToken"]
    refresh = tokens["refreshToken"]

    # -------- DISCOVERY --------
    if args.discover:
        clients, resp = get_clients_visible(host, access, verify_param)

        if resp is not None and resp.status_code in (401, 403):
            try:
                new_a, new_r = safe_renew_and_update(tokens, verify_param)
                access, refresh = new_a, new_r
            except Exception as ex:
                eprint(f"[Commvault] renew falhou (discovery): {ex}")
                print(json.dumps({"data": []}))
                return

            clients, resp = get_clients_visible(host, access, verify_param)

        if resp is None or resp.status_code != 200 or clients is None:
            if resp is not None:
                eprint(f"[Commvault] discovery falhou HTTP {resp.status_code}: {(resp.text or '')[:160]}")
            print(json.dumps({"data": []}))
            return

        data = [{"{#CLIENT}": name} for _, name in sorted(clients.items(), key=lambda x: x[1])]
        print(json.dumps({"data": data}))
        return

    # -------- COUNT POR CLIENT --------
    if not args.client:
        print("0")
        return

    client_name = args.client.strip()
    window = get_allowed_window_for_client(client_name, policies, fallback_window)

    if args.debug:
        eprint(f"[policy] client={client_name} day={current_day_key()} weekend={is_weekend()} window={window}")
        eprint(f"[ssl] verify={verify_param}")

    # Dentro da janela => não alertar
    try:
        if is_now_in_window(window):
            print("0")
            return
    except Exception as ex:
        eprint(f"[Commvault] janela inválida '{window}': {ex}")
        print("0")
        return

    jobs, resp, path_used = get_jobs_payload(host, access, verify_param, args.limit)

    if resp is not None and resp.status_code in (401, 403):
        try:
            new_a, new_r = safe_renew_and_update(tokens, verify_param)
            access, refresh = new_a, new_r
        except Exception as ex:
            eprint(f"[Commvault] renew falhou (jobs): {ex}")
            print("0")
            return

        jobs, resp, path_used = get_jobs_payload(host, access, verify_param, args.limit)

    if args.debug:
        if path_used:
            eprint(f"url_used={host}{path_used}")
        if resp is not None:
            eprint(f"http={resp.status_code}")

    if resp is None or resp.status_code != 200 or jobs is None:
        if resp is not None:
            eprint(f"[Commvault] jobs falhou HTTP {resp.status_code}: {(resp.text or '')[:160]}")
        print("0")
        return

    # Conta jobs ativos deste client (jobs já vem filtrado por job_is_active)
    target = client_name.lower()
    cnt = 0

    for j in jobs:
        # Filtra somente BACKUP (ignora Restore)
        if not job_is_backup_only(j):
            if args.debug and job_is_restore(j):
                eprint(f"[skip] jobId={j.get('jobId')} type={job_type_blob(j)}")
            continue

        # Seu payload usa destClientName em minúsculo (ex.: s154fsbc0001)
        dc = j.get("destClientName")
        if isinstance(dc, str) and dc.strip().lower() == target:
            cnt += 1

    print(str(cnt))


if __name__ == "__main__":
    main()
