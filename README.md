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
