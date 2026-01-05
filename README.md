# Monitoramento Commvault (Jobs “Running” fora do horário) no Zabbix

## Objetivo

Monitorar se existem jobs de backup em execução (status=Running) fora da janela permitida <strong> 00:00–05:45 </strong>  e gerar alerta no Zabbix informando qual client está executando fora do horário.

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
