# Monitoramento Commvault (Jobs “Running” fora do horário) no Zabbix

## Objetivo

Monitorar se existem jobs de backup em execução (status=Running) fora da janela permitida <strong> 18:00-05:45 </strong>  e gerar alerta no Zabbix informando qual client está executando fora do horário.

## 1) Pré-requisitos

## 1.1 Commvault

 - Acesso ao Command Center do Commvault (produção).

- Usuário de integração (ex.: Zabbix) com permissão para:

- visualizar Clients (no escopo definido)

- visualizar Jobs

- Criação de Access Token + Refresh Token no Command Center

<strong>Importante: </strong> não reutilizar o mesmo token em homolog/prod ou em mais de um host. O Commvault pode detectar “token reuse” e purgar o token automaticamente (evento: Token reuse detected… token has been purged).

## 1.2 Host coletor (Linux com Zabbix agent2)

- Diretório: /opt/zabbix/scripts/commvault
- Python 3
- Biblioteca requests:
- ```python3 -c "import requests"```
- Se necessário:
- ```pip3 install requests```

## 2) Criação do token no Commvault (produção)

No Command Center:

1. Security → Users → (usuário Zabbix)

2. Acessar Access tokens

3. Add token

4. Copiar:
- Access token
- Refresh token

5. Definir nome claro (ex.: zabbix-prod-collector-<hostname>) e descrição “Integração Zabbix”.

## 3) Implementação no host coletor

<strong>3.1 Estrutura de diretórios </strong>

```bash
mkdir -p /opt/zabbix/scripts/commvault
chown -R zabbix:zabbix /opt/zabbix/scripts/commvault
chmod 755 /opt/zabbix/scripts/commvault
```

<strong>3.2 Arquivo tokens.json </strong>

Criar /opt/zabbix/scripts/commvault/tokens.json:

```json
{
  "host": "https://<HOST_DO_COMMAND_CENTER>",
  "accessToken": "<ACCESS_TOKEN>",
  "refreshToken": "<REFRESH_TOKEN>"
}
```
Permissões:

```bash
chown zabbix:zabbix /opt/zabbix/scripts/commvault/tokens.json
chmod 600 /opt/zabbix/scripts/commvault/tokens.json
```

<strong> 3.3 Criar o arquivo policies.json </strong> 

Criar em:

`/opt/zabbix/scripts/commvault/policies.json`

```json
{
  "default": {
    "weekday": "18:00-05:45",
    "weekend": "18:00-05:45"
  },

  "CLIENT0001": {
    "weekday": "18:00-05:45",
    "weekend": "20:00-08:00"
  },

  "CLIENT0002": {
    "days": {
      "mon": "18:00-05:45",
      "tue": "18:00-05:45",
      "wed": "18:00-05:45",
      "thu": "18:00-05:45",
      "fri": "18:00-05:45",
      "sat": "22:00-08:00",
      "sun": "22:00-08:00"
    }
  }
}
```

Permissões recomendadas:

```bash
sudo chown zabbix:zabbix /opt/zabbix/scripts/commvault/policies.json
sudo chmod 644 /opt/zabbix/scripts/commvault/policies.json
```

<strong>3.4 Scripts utilizados </strong>

Colocar em <strong> /opt/zabbix/scripts/commvault/: </strong>
- commvault_jobs_by_client.py
   - Discovery (LLD) dos clients visíveis pelo token
   - Contagem de jobs Running por client fora da janela
- Coloque também:
   - <strong> commvault_jobs.py </strong> (contagem geral)
   - <strong> commvault_visible_clients.py </strong> (validação de RBAC / lista de clients)
   - <strong> commvault_job_history.py </strong> (listar o histórico de jobs)
 
  
<strong> commvault_jobs_by_client.py </strong> 

```python
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
RENEW_LOCK_PATH = "/tmp/commvault_token_renew.lock"

# Status "ativos" (fallback caso endpoint filtrado não funcione)
ACTIVE_STATUS = {
    "running", "waiting", "pending", "queued", "active",
    "preparing", "starting", "in progress", "inprogress", "suspended"
}
FINAL_STATUS = {
    "completed", "completed w/ errors", "completed with errors", "failed",
    "killed", "canceled", "cancelled", "skipped", "success"
}

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
            # Sem lock, executa direto
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

            # SEMPRE filtra localmente
            jobs_active = [j for j in jobs if job_is_active(j)]
            return jobs_active, r, path

        # parâmetros não suportados -> tenta próximo
        if r.status_code in (400, 404):
            continue

        # auth/RBAC -> deixa caller tratar renew
        if r.status_code in (401, 403):
            return None, r, path

        # outros erros: devolve
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

    # Compatibilidade: se você quiser forçar uma janela fixa via linha de comando
    ap.add_argument("--allowed-window", default=None, help="Fallback HH:MM-HH:MM (se não houver policy). Ex.: 18:00-05:45")

    # SSL/TLS
    ap.add_argument("--verify-tls", action="store_true", help="Força verify=True (usa trust store do sistema)")
    ap.add_argument("--ca-bundle", default=None, help="Caminho para CA bundle .crt/.pem (verify=<path>)")

    args = ap.parse_args()

    # Defaults
    fallback_window = args.allowed_window.strip() if isinstance(args.allowed_window, str) and args.allowed_window.strip() else "18:00-05:45"

    # Lê tokens/policies
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

        # token inválido/expirado -> tenta renew (com lock)
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

    # token inválido/expirado -> tenta renew (com lock)
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
        dc = j.get("destClientName")
        if isinstance(dc, str) and dc.strip().lower() == target:
            cnt += 1

    print(str(cnt))


if __name__ == "__main__":
    main()
```

<strong> commvault_jobs.py </strong>

```python
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
```

<strong> commvault_visible_clients.py </strong>

```python
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
```

<strong> commvault_job_history.py </strong> 


```python
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

```

De permissão para o script de job history: 

```bash
chmod a+x /opt/zabbix/scripts/commvault/commvault_job_history.py
```

## 4) Configuração do Zabbix Agent2 (UserParameters)

Criar/editar:

<strong>/etc/zabbix/zabbix_agent2.d/commvault.conf</strong>

```ini
UserParameter=commvault.jobs.discovery,/usr/bin/python3 /opt/zabbix/scripts/commvault/commvault_jobs_by_client.py --discover
UserParameter=commvault.jobs.running.client[*],/usr/bin/python3 /opt/zabbix/scripts/commvault/commvault_jobs_by_client.py --client "$1"

# Lista (JSON) dos jobs das últimas 24h (limitado)
UserParameter=commvault.jobs.history24h.json,/usr/bin/python3 /opt/zabbix/scripts/commvault/commvault_job_history.py --since 24h --limit 200 --json

# Lista (JSON) só dos jobs FAILED nas últimas 24h (limitado)
UserParameter=commvault.jobs.failed24h.json,/usr/bin/python3 /opt/zabbix/scripts/commvault/commvault_job_history.py --since 24h --status Failed --limit 200 --json

```
Reinicie:

```bash
systemctl restart zabbix-agent2
```
Testes:

```bash
zabbix_agent2 -t commvault.jobs.discovery
zabbix_agent2 -t commvault.jobs.running.client["CLIENT0001"]
zabbix_agent2 -t commvault.jobs.history24h.json
zabbix_agent2 -t commvault.jobs.failed24h.json

```

## Validação (debug da policy)

Para verificar qual janela está sendo aplicada para um client:

```bash
python3 /opt/zabbix/scripts/commvault/commvault_jobs_by_client.py --client "CLIENT0001" --debug 2>&1
```

<strong> Comportamento </strong> 

Com 18:00–05:45:

- entre 18:00 e 23:59 → permitido (retorna 0)

- entre 00:00 e 05:45 → permitido (retorna 0)

- entre 05:46 e 17:59 → fora do permitido → se tiver job Running, retorna >0 e alerta

## Validações Job History 

<strong> 1) Listar jobs das últimas 24h (padrão) </strong>

```python
python3 /opt/zabbix/scripts/commvault/commvault_job_history.py
```

<strong> 2) Listar histórico de um client nas últimas 7 dias </strong>

```python
python3 /opt/zabbix/scripts/commvault/commvault_job_history.py --client CLIENT0001 --since 7d
```
<strong> 3) Só jobs com status “Failed” nas últimas 24h </strong>

```python
python3 /opt/zabbix/scripts/commvault/commvault_job_history.py --status Failed --since 24h
```

<strong> 4) Saída em JSON (bom para integrar depois) </strong>

```python
python3 /opt/zabbix/scripts/commvault/commvault_job_history.py --client CLIENT0001 --since 24h --json
```


## 5) Template no Zabbix (LLD + itens + triggers)

<strong> 5.1 Link do template </strong> 

O template deve ser vinculado ao host coletor (onde roda o agent2 + scripts).

Caminho:
<strong> Configuration → Hosts → (host coletor) → Templates → Link new templates </strong> 

<strong> 5.2 Discovery Rule (LLD) </strong> 

No template:
<strong> Discovery rules → Create discovery rule </strong> 

- Name: Commvault - Discovery clients visíveis
- Type: Zabbix agent
- Key: commvault.jobs.discovery
- Update interval: 1h

<strong>5.3 Item Prototype </strong>

Dentro da discovery rule:
<strong> Item prototypes → Create item prototype </strong>

- Name: Commvault - Jobs running fora do horário em {#CLIENT}
- Type: Zabbix agent
- Key: commvault.jobs.running.client[{#CLIENT}]
- Type of information: Numeric (unsigned)
- Update interval: 60s

<strong> 5.4 Trigger Prototype </strong> 

Dentro da discovery rule:
<strong> Trigger prototypes → Create trigger prototype </strong> 

- Name: Commvault: Job rodando fora da janela (00:00–05:45) em {#CLIENT}
- Severity: High (ou conforme política)
- Expression:

```perl
last(/<TEMPLATE_NAME>/commvault.jobs.running.client[{#CLIENT}])>0
```

Resultado: o alerta sempre informa qual client está fora do horário via {#CLIENT}.

### Itens Jobs últimas 24h e Jobs FAILED 

Item 1 — Jobs últimas 24h
- Type: Zabbix agent (ou agent active, conforme seu padrão)
- Key: commvault.jobs.history24h.json
- Type of information: Text
- Update interval: 30m ou 1h (recomendado, porque é pesado)
- History storage period: a seu critério (ex.: 7d)

Item 2 — Jobs FAILED últimas 24h
- Key: commvault.jobs.failed24h.json
- Type of information: Text
- Update interval: 30m ou 1h

Depois vá em Latest data e veja o conteúdo



## 6) Operação e validação

<strong> 6.1 Validação funcional </strong>

1. Iniciar um job manual fora da janela permitida (teste controlado)
2. Verificar em Monitoring → Latest data se o item do client retorna >0
3. Confirmar a trigger em Monitoring → Problems

<strong>6.2 Comportamento esperado</strong>

- Dentro da janela (18:00–05:45): sempre retorna 0 (não alerta)
- Fora da janela:
  - sem job: 0
  - com job Running: >0 (alerta)
 
## 7) Troubleshooting (principais causas)

<strong>7.1 “Token reuse detected… token purged” </strong>
 
Causa: mesmo token usado em mais de um local/ambiente.
Ação:

- gerar token novo e usar apenas em um collector
- conferir se não há cópias do tokens.json em outros hosts

<strong>7.2 401/403 “Access denied”</strong>

Causa: falha de auth/API.
Ação:

- checar logs do Zabbix agent2 e o Audit Trail do Commvault
- renovar/gerar novo token
