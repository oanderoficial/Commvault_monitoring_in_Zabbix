# Commvault -Zabbix Monitoring (Jobs “Running” fora da janela)

Este projeto monitora **jobs do Commvault (Command Center API)** e gera alerta no **Zabbix** quando existir **job em execução (Running)** fora da janela permitida.

A solução usa:
- **Python** + **Commvault Command Center API**
- **Login + Refresh Token** (com renovação automática)
- **Zabbix Agent2 UserParameter**
- **Low-Level Discovery (LLD)** para criar itens/triggers por client

---

## Objetivo

Detectar e alertar quando houver **backup rodando fora do horário permitido**.

**Janela permitida (default):** `18:00-05:45`  
- Dentro da janela → retorna `0` (não alerta)
- Fora da janela → se houver job Running → retorna `>0` (alerta)

---

## Arquivos Principais

- `commvault_jobs_by_client.py`
  - `--discover`: retorna LLD JSON com clients visíveis pelo token (RBAC)
  - `--client "<CLIENT>"`: retorna a contagem de jobs Running para o client **fora da janela**
  - Faz **renew** automático do token e atualiza `tokens.json`

- `tokens.json`
  - Armazena `host`, `accessToken`, `refreshToken`

---

## 1. Visão Geral do Projeto

- Monitoramento proativo de jobs Commvault executando fora da janela permitida, com geração de alertas no Zabbix por client.
- Integração via scripts Python executados como UserParameters no Zabbix Agent2.
- Descoberta automática (LLD) dos clients visíveis pela credencial configurada, criando itens e triggers derivados.
- Dois modos de autenticação suportados:
  - Login com usuário/senha para obter Authtoken (caching local).
  - Access/Refresh Token com renovação automática para histórico e utilitários.
- Políticas de janela por client configuráveis via `policies.json` (por dia, por weekday/weekend, ou default).

Recursos:
- Scripts: [commvault_jobs_by_client.py], [commvault_jobs.py], [commvault_job_history.py], [commvault_visible_clients.py]
- Template Zabbix: [Template Backup Commvault - Janela.yaml]
- Guia detalhado de implementação: [implementação.md]

---

## 2. Requisitos

Infraestrutura:
- Commvault Command Center acessível (produção) com usuário de integração e escopo RBAC adequado.
- Host coletor com Zabbix Agent2.
- Acesso de rede HTTPS ao Command Center (porta 443).

Software:
- Python 3 instalado no host coletor.
- Biblioteca `requests`.
- Permissões de arquivo corretas para tokens e políticas.

TLS/Certificados:
- Recomendado habilitar `verify=True` ou apontar `verify="/caminho/ca-bundle.crt"`.
- Passo a passo: ver [SSL_VERIFICATION.md].

---

## 3. Arquitetura do Sistema

Componentes:
- Zabbix Agent2
  - UserParameters que invocam os scripts Python.
  - Discovery (LLD) de clients, itens e triggers por client.
- Scripts Python
  - Descoberta: lista clients visíveis via API.
  - Checagem: conta jobs de backup ativos fora da janela por client.
  - Histórico: lista jobs com filtros (status, período, client) em JSON ou tabela.
- Configuração
  - `tokens.json` (modo Authtoken): host, usuário, senha e opções SSL.
  - `tokens_history.json` (modo Bearer): host, accessToken, refreshToken.
  - `policies.json`: janelas permitidas por client/dia.
  - Cache: `.cv_authtoken_cache.json` com TTL para reduzir logins.
  - Logs: `commvault_jobs_by_client.log` (debug e eventos).

Fluxo Alto Nível:
- LLD: chama `--discover` e produz JSON com `{#CLIENT}`.
- Item por client: verifica se “agora” está fora da janela → busca jobs ativos (backup-only) → conta e retorna valor.
- Trigger: dispara se valor `> 0`.

Interfaces:
- Commvault Command Center API (Login, Client, Job).
- Zabbix Agent2 (UserParameter, LLD, Item/Trigger).

---

## 4. Modelagem de Dados

`zabbix/scripts/commvault/tokens.json` (Authtoken):
```json
{
  "host": "https://<HOST_DO_COMMAND_CENTER>",
  "username": "USUÁRIO",
  "password": "SENHA",
  "domain": "",
  "commserver": "",
  "verifyTLS": false,
  "caBundle": ""
}
```

`zabbix/scripts/commvault/tokens_history.json` (Bearer):
```json
{
  "host": "https://<HOST_DO_COMMAND_CENTER>",
  "accessToken": "<ACCESS_TOKEN>",
  "refreshToken": "<REFRESH_TOKEN>"
}
```

`zabbix/scripts/commvault/policies.json`:
```json
{
  "default": { "weekday": "18:00-05:45", "weekend": "18:00-05:45" },
  "CLIENT0001": { "weekday": "18:00-05:45", "weekend": "20:00-08:00" },
  "CLIENT0002": { "weekday": "19:00-06:00", "weekend": "00:00-23:59" },
  "CLIENT0003": {
    "days": { "mon": "18:00-05:45", "tue": "18:00-05:45", "wed": "18:00-05:45",
              "thu": "18:00-05:45", "fri": "18:00-05:45", "sat": "22:00-08:00", "sun": "22:00-08:00" }
  }
}
```

LLD Discovery (saída de `--discover`):
```json
{ "data": [ { "{#CLIENT}": "CLIENT0001" }, { "{#CLIENT}": "CLIENT0002" } ] }
```

Cache de Authtoken (`.cv_authtoken_cache.json`):
```json
{ "<host>": { "authtoken": "<token>", "expiresAt": 1730000000, "loginBackoffUntil": 0 } }
```

---

## 5. Fluxos e Regras de Negócio

Seleção de Janela:
- Ordem de prioridade: dias do client → weekday/weekend do client → default → fallback CLI.
- Implementação: ver função de seleção em [commvault_jobs_by_client.py]

Determinação de “ativo”:
- Heurística considera status e ausência de `jobEndTime` ou `%complete < 100`.
- Implementações: [commvault_jobs_by_client.py] [commvault_jobs.py][commvault_job_history.py]

Filtro “backup-only”:
- Ignora restores; aceita somente `opType` em `{4, 59}` ou nomes com “backup”.
- Implementação: [commvault_jobs_by_client.py].

Autenticação e Cache:
- Authtoken com TTL (default 50 min) e backoff para falhas de login.
- Renovação de Bearer tokens com lock dedicado no histórico.
- Implementações: cache e login em [commvault_jobs_by_client.py]

SSL/TLS:
- Parametrização `verify` via `--verify-tls` ou `--ca-bundle` e/ou campos em tokens.
- Implementações: `build_verify_param` em [commvault_jobs_by_client.py] e [commvault_job_history.py].

---

## 6. Setup e Execução do Projeto (README Técnico)

Diretórios:
- Criar `/opt/zabbix/scripts/commvault` e ajustar permissões (zabbix:zabbix).
- Copiar os scripts do diretório [zabbix/scripts/commvault].

Configuração:
- `tokens.json` (Authtoken) e `tokens_history.json` (Bearer) conforme a modelagem.
- `policies.json` com janelas por client.
- Ajustar permissões: `chmod 640 tokens*.json`, `chmod 644 policies.json`, `chmod 750` no diretório.

Zabbix Agent2 (UserParameters):
- Arquivo `/etc/zabbix/zabbix_agent2.d/commvault.conf`:
  - `commvault.jobs.discovery`: LLD de clients.
  - `commvault.jobs.running.client[*]`: contagem por client.
  - `commvault.jobs.history24h.json` e `commvault.jobs.failed24h.json`: dados em JSON.
- Reiniciar agente e validar com `zabbix_agent2 -t <key>`.

Template:
- Importar e vincular o template [Template Backup Commvault - Janela.yaml] ao host coletor.

Guia detalhado:
- Passo a passo com exemplos está em [implementação.md].

---

## 7. APIs e Interfaces

Commvault Command Center:
- Login: `POST /commandcenter/api/Login` (retorna Authtoken).
- Clients: `GET /commandcenter/api/Client?limit=5000`.
- Jobs: `GET /commandcenter/api/Job?...` com filtros (status, categoria).
- Headers:
  - Authtoken: `Authtoken: <token>` (modo login).
  - Bearer: `Authorization: Bearer <accessToken>` (modo tokens).

Zabbix:
- UserParameters para executar scripts.
- LLD produz `{#CLIENT}` para item/trigger prototypes.
- Keys principais:
  - `commvault.jobs.discovery`
  - `commvault.jobs.running.client[{#CLIENT}]`
  - `commvault.jobs.history24h.json`
  - `commvault.jobs.failed24h.json`

CLI dos scripts:
- `commvault_jobs_by_client.py`: `--discover`, `--client`, `--allowed-window`, `--verify-tls`, `--ca-bundle`, `--token-ttl`, `--limit`, `--debug`.
- `commvault_job_history.py`: `--since`, `--client`, `--status`, `--active-only`, `--json`, `--verify-tls`, `--ca-bundle`, `--limit`.
- `commvault_jobs.py`: `--allowed-window`, `--verify-tls`, `--limit`, `--debug`.

---

## 8. Testes e Qualidade

Validações rápidas:
- `zabbix_agent2 -t commvault.jobs.discovery`
- `zabbix_agent2 -t commvault.jobs.running.client["CLIENT0001"]`
- `zabbix_agent2 -t commvault.jobs.history24h.json`
- `zabbix_agent2 -t commvault.jobs.failed24h.json`

Debug:
- Incluir `--debug` para ver URL/HTTP e janela aplicada.
- Usar `--json` no histórico para inspeção programática.

Boas práticas:
- Adicionar testes unitários simples para:
  - `is_now_in_window`, `parse_allowed_window`.
  - `job_is_active`, `job_is_backup_only`.
  - Seleção de janela em `policies.json`.
- Opcional: empacotar scripts em módulo Python para facilitar testes.

---

## 9. Segurança

TLS:
- Habilitar verificação de certificado (`verify=True`) ou CA bundle dedicado.
- Guia completo: [SSL_VERIFICATION.md].

Credenciais:
- NUNCA reutilizar o mesmo token em múltiplos hosts/ambientes.
- Arquivos `tokens*.json` com permissões restritas (640) e propriedade `zabbix:zabbix`.
- Evitar logar segredos; logs de debug não imprimem tokens.

Resiliência:
- Backoff automático após falhas de login para evitar bloqueios.
- Lock dedicado ao renew no histórico para evitar corrida.

Compliance:
- Não versionar segredos reais; manter placeholders e instruções de provisionamento.

---

## 10. Roadmap e Decisões

Decisões atuais:
- Suportar ambos os modos de autenticação (Authtoken vs Bearer) conforme caso de uso.
- Janelas configuráveis por client via `policies.json` com prioridade clara.

Próximos passos:
- Unificar autenticação: avaliar migração total para Authtoken ou Bearer, documentando prós/contras.
- Ativar TLS verificado por padrão (`verifyTLS: true`) e exigir CA bundle.
- Centralizar configuração (arquivo único com perfil por ambiente).
- Empacotar como projeto Python com entrypoints CLI e testes.
- Adicionar métricas e logs estruturados (JSON) para observabilidade.
- Validar limites/consulta de Jobs com paginação quando necessário.

Referências:
- Scripts: [jobs_by_client], [jobs], [job_history], [visible_clients]
- Template: [Template Backup Commvault - Janela.yaml]
- Implementação detalhada: [implementação.md]

### No host coletor
- Python 3
- requests:
  ```bash
  python3 -c "import requests"
