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

<strong>3.3 Scripts utilizados </strong>

Colocar em <strong> /opt/zabbix/scripts/commvault/: </strong>
- commvault_jobs_by_client.py
   - Discovery (LLD) dos clients visíveis pelo token
   - Contagem de jobs Running por client fora da janela
- Coloque também:
   - <strong> commvault_jobs.py </strong> (contagem geral)
   - <strong> commvault_visible_clients.py </strong> (validação de RBAC / lista de clients)
 
<strong> commvault_jobs_by_client.py </strong> 

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
