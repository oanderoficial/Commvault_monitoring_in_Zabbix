# Habilitar verificação SSL/TLS (verify=True) no monitoramento Commvault → Zabbix

Este guia mostra como sair do modo “inseguro” (`verify=False`) e habilitar **validação de certificado** (SSL/TLS) nas chamadas Python `requests` usadas nos scripts de monitoramento do Commvault.

## Por que habilitar?
Com `verify=False`, o script aceita qualquer certificado, o que abre margem para:
- MITM (interceptação)
- DNS spoofing
- certificados inválidos/expirados passarem despercebidos

O recomendado em produção é:
- **Instalar a CA interna** (ou cadeia completa) no host coletor
- Habilitar `verify=True` (ou usar um CA bundle específico)

---

## Visão geral das opções

### Opção A (recomendada): confiar na CA do sistema
1. Instalar CA interna no sistema (trust store)
2. Scripts passam a usar `verify=True` (sem precisar indicar arquivo)

* Vantagens: simples, padrão, funciona para todos os scripts  
* Requer acesso para instalar CA no SO

### Opção B: usar CA bundle específico no script
1. Salvar um arquivo `.crt` (CA/root/intermediates)
2. Passar `verify="/caminho/ca-bundle.crt"` no `requests`

 
* Vantagens: não mexe no trust store global  
* Requer manter o arquivo e apontar no script

---

## Passo 1 — Obter a cadeia de certificados do Command Center

No host coletor (Linux), rode:

```bash
HOST="seu_host.empresa.net"
echo | openssl s_client -connect ${HOST}:443 -servername ${HOST} -showcerts 2>/dev/null | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > commvault-chain.pem
```

## Instalar a CA/chain no trust store do sistema (recomendado)

<strong> Ubuntu/Debian </strong> 

```bash
sudo cp /opt/zabbix/scripts/commvault/commvault-chain.pem \
  /usr/local/share/ca-certificates/commvault-chain.crt

sudo update-ca-certificates

```

<strong> RHEL/CentOS/Rocky/Alma </strong>

```bash
sudo cp /opt/zabbix/scripts/commvault/commvault-chain.pem \
  /etc/pki/ca-trust/source/anchors/commvault-chain.crt

sudo update-ca-trust extract

```

<strong> Teste rápido com curl </strong> 

```bash
curl -I https://s154mscommv1.br154.tbintra.net/commandcenter/ | head
```

Se não houver erro de certificado, a CA foi instalada corretamente.

## Teste de validação SSL via Python (verify=True)

Após instalar a CA (ou configurar CA bundle), valide com:

```bash
python3 - <<'PY'
import json, requests
t=json.load(open("/opt/zabbix/scripts/commvault/tokens.json"))
host=t["host"].rstrip("/")
token=t["accessToken"]

r=requests.get(
  f"{host}/commandcenter/api/Client?limit=1",
  headers={"Accept":"application/json","Authorization":f"Bearer {token}"},
  timeout=30,
  verify=True
)
print("HTTP", r.status_code)
print(r.text[:200])
PY
```

Esperado: HTTP 200.

## Alternativa (sem mexer no sistema): usar o bundle diretamente no script

Se você não quiser instalar CA no sistema, você pode usar o arquivo como CA bundle:

```bash
cd /opt/zabbix/scripts/commvault
cp commvault-chain.pem commvault-chain.crt
sudo chown zabbix:zabbix commvault-chain.crt
sudo chmod 644 commvault-chain.crt
```

Depois, no script Python, use:

<strong> verify="/opt/zabbix/scripts/commvault/commvault-chain.crt" </strong>
- em vez de verify=False.



