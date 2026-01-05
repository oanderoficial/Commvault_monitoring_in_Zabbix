# Commvault -Zabbix Monitoring (Jobs “Running” fora da janela)

Este projeto monitora **jobs do Commvault (Command Center API)** e gera alerta no **Zabbix** quando existir **job em execução (Running)** fora da janela permitida.

A solução usa:
- **Python** + **Commvault Command Center API**
- **Access Token + Refresh Token** (com renovação automática)
- **Zabbix Agent2 UserParameter**
- **Low-Level Discovery (LLD)** para criar itens/triggers por client

---

## Objetivo

Detectar e alertar quando houver **backup rodando fora do horário permitido**.

**Janela permitida (default):** `18:00-05:45`  
- Dentro da janela → retorna `0` (não alerta)
- Fora da janela → se houver job Running → retorna `>0` (alerta)

---

## Arquivos

- `commvault_jobs_by_client.py`
  - `--discover`: retorna LLD JSON com clients visíveis pelo token (RBAC)
  - `--client "<CLIENT>"`: retorna a contagem de jobs Running para o client **fora da janela**
  - Faz **renew** automático do token e atualiza `tokens.json`

- `tokens.json`
  - Armazena `host`, `accessToken`, `refreshToken`

---

## Pré-requisitos

### No host coletor
- Python 3
- requests:
  ```bash
  python3 -c "import requests"
