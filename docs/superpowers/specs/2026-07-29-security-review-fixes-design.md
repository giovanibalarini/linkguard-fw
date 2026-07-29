# Correção dos achados da revisão de segurança de 2026-07-29

**Data:** 2026-07-29
**Status:** aprovado (usuário pediu "Corrigir todos e testar o produto se nada quebrou" — instrução
direta, sem espaço de design a explorar; este documento registra as decisões técnicas de cada
correção, servindo de base pro plano de implementação, não é um gate de aprovação humana)

---

## 1. Escopo

18 dos 19 achados da revisão de segurança (ver relatório da revisão, mesma sessão). O achado #19
("integridade de update é só checksum, sem assinatura independente") foi explicitamente marcado como
**já aceito, informativo, não é regressão** — fica de fora do escopo de correção.

Cada achado abaixo tem: o problema (resumo), a decisão de correção, e o porquê — porque vários exigiam
uma escolha de design real (não é só "adicionar uma regex"), especialmente #6 (revogação de sessão) e
#4 (iptables legado).

## 2. Críticos

### 2.1 Injeção de config do WireGuard → RCE como root

`internal/wireguard/wireguard.go`'s `ServerConfig()` escreve `/etc/wireguard/wg0.conf` via
`fmt.Fprintf` cru, sem filtrar newline, pros campos `Config.Address` e `Peer.Name` (`Peer.AllowedIP`/
`PublicKey` são sempre gerados pelo servidor — `wireguard.NextAllowedIP`/`GenerateKeypair` — nunca
vêm do cliente, confirmado lendo `AddPeer`). Um `\n` em qualquer um dos dois campos injeta uma
diretiva `PostUp`/`[Peer]` nova no arquivo, executada como root pelo `wg-quick` no restart seguinte
(`Apply()` já chama `systemctl restart wg-quick@wg0` logo após escrever o arquivo).

**Decisão**: validar antes de aceitar.
- `Config.Address`/`Config.Subnet`: `net.ParseCIDR` (rejeita qualquer coisa que não seja `ip/prefixo`
  válido — estruturalmente impossível ter newline/aspas/`;` num CIDR válido).
- `Config.Endpoint`: regex de hostname RFC 1952-ish ou IP — não é o vetor de RCE confirmado (não é
  escrito em `wg0.conf`, só aparece no `.conf` do cliente devolvido ao navegador), mas corrigido por
  higiene já que a spec original já pedia formato correto.
- `Config.DNS`: `net.ParseIP`.
- `Peer.Name`: regex de charset seguro (`^[\p{L}\p{N} ._-]{1,64}$` — letras Unicode/dígitos/espaço/
  ponto/hífen/underscore, sem newline/aspas/`#`/`;`) — é rótulo de exibição, não endereço de rede, por
  isso regex de charset em vez de `ParseCIDR`.

### 2.2 Escalação de privilégio via `users.manage`

`PUT /api/users/{id}` (`internal/api/handlers/users.go`) só exige `users.manage` e só confere que os
papéis referenciados *existem* (`validateRoles`) — nunca que o ator já detém as permissões que está
concedendo, nem impede auto-atribuição (diferente de `Delete`, que bloqueia auto-exclusão
explicitamente).

**Decisão**: `Update` passa a exigir `roles.manage` **também**, além de `users.manage`, sempre que o
corpo da requisição inclui `role_ids` (trocar senha continua só precisando de `users.manage` — não
concede nem revoga permissão nenhuma). Alternativa considerada e descartada: checar
"o papel-alvo não pode exceder o que o ator já tem" — mais correto em teoria, mas exige computar o
conjunto de permissões do ator em tempo de request e comparar conjunto-a-conjunto, complexidade bem
maior pro mesmo resultado prático (as duas permissões — `users.manage` e `roles.manage` — já
representam exatamente a separação que o produto pretende: quem só gerencia usuários não deveria
poder tocar em papel nenhum, nem o próprio). Isso também fecha implicitamente a auto-promoção: uma
conta com só `users.manage` não passa mais no `require(roles.manage)` da própria troca de papel.

## 3. Importantes

### 3.1 `PortForward.Interface` sem validação de charset

`internal/nftables/service.go`'s `dnatRule()` valida `Proto`/`ExtPort`/`DestPort`/`DestIP`, mas
`Interface` só recebe `TrimSpace` no handler, pulando o `reIface` (`^[a-zA-Z0-9._-]{1,15}$`) que
`RuleFields.Iif`/`.Oif` já usam no mesmo arquivo, poucas linhas abaixo.

**Decisão**: aplicar `reIface` (exportado do `nftables` como já é usado internamente, ou reimplementado
como valor idêntico no handler) em `PortForward.Interface` antes de `dnatRule()` — mesmo padrão já
usado pros outros campos de interface do arquivo. Correção mecânica, sem ambiguidade de design.

### 3.2 `validateRuleSpec` do iptables legado é denylist, não allowlist

Único chamador real deste endpoint no frontend inteiro é o assistente de balanceamento WAN
(`web/src/pages/Links.tsx:255-263`), sempre no formato
`-s <LAN> -m conntrack --ctstate NEW [-m statistic --mode random --probability <p>] -j MARK --set-mark <0x1|0x2>`,
`table=mangle`, `chain=PREROUTING`. `validateRuleSpec` hoje só bloqueia flags de *gerência* de regra
(`-A`/`-I`/`-F`/etc.) — não restringe `-j`/`-m`/valores, então o campo livre de LAN do assistente
(`wizardLan`, só checado como não-vazio) vira tokens extras de argv do `iptables` real.

**Decisão**: reescrever `validateRuleSpec` como uma gramática allowlist explícita cobrindo só os
tokens que o único uso legítimo precisa: `-s <CIDR válido via net.ParseCIDR>`, `-m
{conntrack,statistic}`, `--ctstate <lista de NEW/ESTABLISHED/RELATED/INVALID>`, `--mode
{random,nth}`, `--probability <float 0-1>`, `-j {ACCEPT,DROP,REJECT,RETURN,MARK}`, `--set-mark
<0x[0-9a-fA-F]+>`. Qualquer token fora desse conjunto rejeita a regra inteira. `table`/`chain`
também passam a ser validados contra os valores que o assistente realmente usa (`mangle`/
`PREROUTING`) — CreateRule/ReplaceRule aceitam só esses dois valores por ora (outros usos futuros
exigiriam estender a lista explicitamente, não abrir de novo pra qualquer string). O frontend
(`wizardLan`) ganha validação de CIDR antes de montar a requisição — melhoria de UX (erro na hora),
não é a barreira real (essa é a validação server-side).

### 3.3 JWT secret sem checagem de força/vazio na inicialização

`config.Load()` nunca valida `JWTSecret` antes de `auth.NewService` assinar/validar tokens com ele.
`deploy/install.sh` (documentado no README como caminho oficial) grava `jwt_secret: ""` e só imprime
aviso — nada no código Go impede o serviço de subir e assinar tokens com chave HMAC vazia.

**Decisão**: `cmd/linkguard-fw/main.go` falha o boot (log fatal, processo não sobe) se
`len(cfg.JWTSecret) < 32` bytes. Fail-closed explícito na inicialização, não um aviso que pode ser
ignorado. 32 bytes é o mínimo razoável pra HMAC-SHA256 (256 bits) sem forçar re-geração de instalações
já corretas (`deploy/deb/postinst` já gera 64 chars aleatórios, bem acima do piso).

### 3.4 Reset de senha / exclusão de usuário não revoga tokens já emitidos

Token JWT não carrega nenhuma noção de "versão" de credencial; `Middleware` só valida assinatura +
expiração (24h), nunca consulta o banco pra saber se a senha mudou depois que o token foi emitido.

**Decisão**: nova coluna `password_version INTEGER NOT NULL DEFAULT 1` na tabela `users` (migração
nova, seguindo o padrão de `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` já que é a primeira coluna
adicionada numa tabela existente neste projeto — todas as anteriores foram `CREATE TABLE IF NOT
EXISTS` de tabelas novas). `UpdateUserPassword` incrementa essa coluna a cada troca. O claim novo
`pwd_ver` no JWT é gravado no login (valor de `user.PasswordVersion` na hora); `Middleware` passa a
fazer **uma consulta ao banco por requisição autenticada** (`GetUserByID`) pra comparar
`claims.PasswordVersion` contra o valor atual — diferença ou usuário inexistente (cobre exclusão
também) → 401. Isso adiciona uma consulta que hoje não existe no `Middleware` (só `Require` consulta
o banco); aceitável dado o volume de tráfego de um painel administrativo doméstico/SMB, não um serviço
de alto QPS — e `Require` já paga esse custo por rota mutante mesmo hoje. Alternativa descartada:
blacklist de tokens revogados (mais peso operacional — precisa de limpeza periódica — pro mesmo
resultado que um contador simples já resolve).

### 3.5 Canal WhatsApp: URL redirecionável vaza o token real

Diferente do Telegram (host fixo `api.telegram.org`), `WhatsAppCfg.URL` é campo livre editável; o
token real (Bearer) é anexado a qualquer host configurado ali.

**Decisão**: fixar o host do WhatsApp (`defaultWhatsAppURL`, já existe como constante) como o único
destino possível — remover `URL` de `WhatsAppCfg`/da UI, mesmo tratamento que `Telegram` já recebe.
Se um dia for necessário apontar pra outro provedor White-label da mesma API, isso vira uma decisão de
produto explícita (permissão dedicada, não `system.write` genérico) — fora de escopo aqui.

### 3.6 Erro interno cru (`err.Error()`) devolvido ao cliente, sistêmico

69 ocorrências em 23 arquivos do padrão `writeError(w, http.StatusInternalServerError, err.Error())`.

**Decisão**: novo helper `writeInternalError(w http.ResponseWriter, err error)` em
`internal/api/handlers/helpers.go` — loga o erro real via `slog.Error` (rastreável no servidor) e
devolve `writeError(w, 500, "erro interno do servidor")` (genérico) ao cliente. Substituição mecânica
das 69 ocorrências do padrão exato pelo helper novo — mesma transformação em todo lugar, sem
julgamento por arquivo.

### 3.7 `sh -c` isolado depende de validação numa função diferente

`internal/stresstest/service.go`'s `armWatchdog` é o único uso de `sh -c` no projeto inteiro; seguro
hoje porque `t.Interface` já foi validado em `Start()` antes do `Test` ser construído, mas nada
garante isso localmente.

**Decisão**: revalidar `t.Interface` contra o mesmo regex de interface (`reIface`-equivalente) dentro
do próprio `armWatchdog`, como defesa em profundidade — se a validação em `Start()` algum dia for
contornada ou uma nova chamada aparecer, `armWatchdog` recusa sozinho em vez de confiar cegamente.

## 4. Menores

### 4.1-4.3 Endurecimento do backup (agrupados, mesmo arquivo/domínio)
- **scrypt** (`internal/backupcrypt/backupcrypt.go`): confirmado no código que `N`/`r`/`p` são
  constantes fixas no Go, **não fazem parte do formato serializado** — um `.lgbak` já emitido hoje
  (`magic="LGB1"`) só decifra corretamente se `Decrypt` usar o MESMO `N` do `Encrypt` que o gerou.
  Subir `N` in-place quebraria a restauração de qualquer backup já enviado por e-mail ou baixado
  antes da correção (falso negativo: "senha incorreta ou arquivo inválido" mesmo com a senha certa).
  **Decisão**: versionar o formato. Magic novo `"LGB2"` embute `N` como 4 bytes big-endian logo após
  o magic (`r`/`p` continuam constantes de código nas duas versões — não há indício de que precisem
  variar independentemente de `N`). `Decrypt` ramifica pelo magic: `"LGB1"` → `N=32768` fixo (layout
  antigo, salt logo após os 4 bytes de magic); `"LGB2"` → lê `N` dos bytes seguintes (salt desloca 4
  bytes). `Encrypt` sempre escreve `"LGB2"` com `N=131072` (2^17). Isso decifra arquivos antigos E
  novos corretamente, sem exigir que o usuário re-baixe/reenvie nada.
- **Rate-limit no restore** (`internal/api/handlers/backup.go`): reaproveitar o mesmo mecanismo de
  lockout por tentativa que `auth.Service` já tem (`maxFailedAttempts`/`lockoutDuration`), mas com uma
  instância própria (não é login, é um endpoint diferente) — chave por usuário autenticado (já
  garantido por `system.write`), não por IP (sessão já é conhecida).
- **`MaxBytesReader`** no restore: `http.MaxBytesReader(w, r.Body, 32<<20)` antes de
  `ParseMultipartForm`, tornando o limite real, não só de buffer de memória.

### 4.4-4.5 Endurecimento global de DoS (agrupados)
- `http.MaxBytesReader` aplicado globalmente via middleware em `internal/api/server.go` (cap
  generoso, ex.: 10MB — nenhuma rota legítima da API precisa de mais que isso, exceto o restore de
  backup que já tem seu próprio cap de 32MB acima, então o middleware global não deve se aplicar a
  essa rota especificamente, ou o cap global deve ser >= 32MB para não conflitar).
- Teto de `limit` de paginação em `internal/api/handlers/logs.go`/`failover.go` (clamp em 1000).

### 4.6-4.8 Higiene de autenticação (agrupados, mesmos arquivos)
- **Login com tempo constante**: `internal/auth/service.go`'s `Login` sempre paga o custo do bcrypt,
  mesmo quando o usuário não existe — comparar contra um hash bcrypt fixo/dummy quando `user == nil`
  antes de retornar erro, igualando o tempo de resposta entre "usuário não existe" e "senha errada".
- **Remover fallback de cookie morto**: `internal/auth/middleware.go`'s `extractToken` — apagar o
  bloco `r.Cookie("token")`, deixando só o header `Authorization`.
- **Auditoria de login**: `internal/api/handlers/auth.go`'s `Login` passa a chamar `auditAction` nos
  3 desfechos (sucesso, falha, bloqueio por tentativas) — `resource` carrega `"user:"+username`
  (submetido, não resolvido, já que um username inválido também deve aparecer no log).

### 4.9 SMTP sem forçar STARTTLS
`internal/notify/notify.go`'s `sendEmail`/`SendEmailAttachment`: sem mudança de comportamento por
padrão (mesmo trust boundary do webhook já aceito — quem configura o relay é `system.write`), mas
documentar explicitamente no comentário do código que isso é uma decisão consciente, não um
descuido — sem ação de código requerida além do comentário. (Se o usuário quiser forçar STARTTLS no
futuro, é uma mudança de comportamento observável — quebra relay legado sem STARTTLS — que merece
pergunta separada, não decisão unilateral aqui.)

## 5. Testes

Cada tarefa do plano de implementação inclui teste Go cobrindo o comportamento corrigido (TDD real,
padrão já estabelecido no projeto). Ao final de todas as tarefas: suíte completa
(`go test ./... -race -count=1`), build completo (`go build ./...`), build do frontend
(`npm run build`), e teste manual em produção dos fluxos afetados mais sensíveis (login, VPN, RBAC)
antes do usuário considerar a correção concluída — replicando o padrão já usado na feature de backup
cifrado desta mesma sessão.
