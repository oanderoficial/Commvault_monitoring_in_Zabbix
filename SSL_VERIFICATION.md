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

✅ Vantagens: simples, padrão, funciona para todos os scripts  
⚠️ Requer acesso para instalar CA no SO

### Opção B: usar CA bundle específico no script
1. Salvar um arquivo `.crt` (CA/root/intermediates)
2. Passar `verify="/caminho/ca-bundle.crt"` no `requests`

✅ Vantagens: não mexe no trust store global  
⚠️ Requer manter o arquivo e apontar no script

---

## Passo 1 — Obter a cadeia de certificados do Command Center

No host coletor (Linux), rode:

```bash
HOST="seu_host.empresa.net"
echo | openssl s_client -connect ${HOST}:443 -servername ${HOST} -showcerts 2>/dev/null | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > commvault-chain.pem
