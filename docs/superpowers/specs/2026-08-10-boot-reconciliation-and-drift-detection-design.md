# Auto-reconciliação no boot + auto-vigilância de deriva de configuração

## 1. Motivação (o incidente e o problema de confiança)

Depois de um reboot de produção em 2026-08-10, a interface física da WAN1
"Vivo" mudou de nome (`enp4s0` → `enp5s0` — nomeação PCI instável, já
documentada). Três coisas ficaram desatualizadas em cascata, **sem o
LinkGuard corrigir nem avisar**:

1. `/etc/network/interfaces` (ifupdown — fora do escopo do LinkGuard hoje).
2. O registro do Link "WAN VIVO" no banco (`links.interface = enp4s0`).
3. A regra de masquerade (NAT) gerada pelo LinkGuard dentro de
   `table inet linkguard`, no `/etc/nftables.conf` — continuou apontando pra
   `enp4s0`, então o NAT da WAN1 não funcionou e o operador teve que subir
   uma regra `iptables` na mão pra restaurar a internet.

Além disso, descobriu-se um quarto ponto: `/etc/resolv.conf` apontando pro
DNS do provedor em vez de `127.0.0.1` (o unbound local) — **nunca teve dono
no código do LinkGuard** (busca por "resolv.conf" no repositório: zero
referências). O `dhclient` da WAN DHCP reescreve esse arquivo a cada
renovação de lease.

Auditoria dos 8 pontos de auto-cuidado no boot (`Ensure*` em
`cmd/linkguard-fw/main.go`): 5 reconciliam corretamente todo boot
(`EnsureForwarding`, `EnsureSteerRouting`, `EnsureAccounting`,
`timesync.EnsureEnabled`, `EnsureKeaDirReadable`). Dois são bootstrap-only
por decisão consciente e defensável (`EnsureDefaultRoles` pra papéis
customizáveis, `tlscert.EnsureSelfSigned`). **`nftables.EnsureTable` é o
único trap não-intencional**: checa se `table inet linkguard` existe e, se
sim (todo boot de máquina já provisionada), retorna sem fazer nada — e é o
único dos oito que **não emite log algum** no caminho no-op.

E o sistema de health-check (`internal/monitoring`) que alimenta o painel é
**estruturalmente cego** a "a config que apliquei bate com a realidade
viva?": ele checa liveness de processo (`systemctl is-active nftables` —
verdinho mesmo com regra podre dentro), métricas de runtime (CPU, disco,
link up/down, NTP), mas nada compara o estado aplicado com o estado real.

Pedido explícito do operador: *"preciso ganhar confiança neste software.
Ele toma conta de um firewall, precisa se responsabilizar e emitir logs
caso não consiga algo. Eu deveria só olhar pro painel pra achar um problema,
e não ficar olhando coisas do sistema."*

## 2. Princípio inegociável

Todo estado que o LinkGuard **aplica**, ele passa a garantir em duas frentes:

- **Reconciliar (ação):** re-deriva o estado a partir da fonte de verdade em
  **todo boot** (idempotente, seguro repetir), não só na primeira vez.
- **Vigiar (visibilidade):** um item de saúde compara o **aplicado** com a
  **realidade viva** e fica vermelho no painel + dispara alerta quando
  divergem — e loga quando não consegue reconciliar.

Reconciliar sem vigiar = deriva silenciosa (foi o incidente). Vigiar sem
reconciliar = o operador de volta no SSH. As duas juntas são o que deixa o
painel confiável como painel único.

## 3. Reconciliar a regra de masquerade (NAT) em todo boot

### Hoje
`nftables.EnsureTable` (`internal/nftables/bootstrap.go`) só cria a tabela se
ela não existir. A regra de masquerade dentro do chain `postrouting` é
escrita uma única vez, na vida do appliance, e nunca mais reconciliada —
nem no boot, nem quando um Link é editado/auto-detectado pela UI (busca por
`postrouting`/`masquerade` no projeto: só existe em `bootstrap.go`).

### Novo
- Uma nova operação `Service.ReconcileMasquerade(ctx, wanInterfaces []string)
  error` roda em **todo boot**, logo depois de `EnsureTable` (que continua
  responsável só por criar a estrutura base quando ela não existe).
- Ela reconstrói cirurgicamente só a regra de masquerade do chain
  `postrouting`: `nft flush chain inet linkguard postrouting` seguido de
  `nft add rule inet linkguard postrouting oifname { <wans> } masquerade`
  (não faz flush da tabela inteira — não toca em `host_wan`, `blocklist`,
  `user_rules`, etc). Idempotente: rodar de novo com as mesmas WANs produz
  exatamente o mesmo estado.
- Fonte de verdade: as interfaces dos Links WAN configurados (`links` no
  banco), sanitizadas pelo mesmo `reIface`/`sanitizeInterfaces` que o
  bootstrap já usa (anti-injeção).
- Persiste via `Service.Persist` pra sobreviver ao próximo reboot.
- **Loga** no INFO as interfaces que aplicou; WARN em falha.
- O mesmo `ReconcileMasquerade` é chamado quando um Link é
  criado/editado/removido/auto-detectado pela UI — fechando o buraco de "editar
  Link não mexe no firewall".

### Coexistência com a regra iptables manual
A regra manual de emergência do operador vive em `table ip nat` (subsistema
`iptables-nft`), tabela **diferente** de `table inet linkguard`. As duas
coexistem sem conflito (masquerade é idempotente). Uma vez que a regra do
LinkGuard esteja reconciliada e o vigia da §5 confirme o NAT correto, a
regra manual pode ser removida — mas isso é limpeza operacional, não código.

## 4. LinkGuard passa a ser dono do `/etc/resolv.conf`

### Hoje
Ninguém no código do LinkGuard gerencia `/etc/resolv.conf`. O appliance roda
unbound como resolver local (127.0.0.1 + IP da LAN), mas o `dhclient` da WAN
DHCP sobrescreve `resolv.conf` com os nameservers do provedor a cada
renovação de lease.

### Novo
- `EnsureResolvConf(ctx, exec firewall.Executor)` — mesmo padrão dos outros
  `Ensure*`, chamado no startup do `main.go`, roda em todo boot, best-effort
  (WARN em falha, não bloqueia o boot):
  1. Escreve `/etc/resolv.conf` = `nameserver 127.0.0.1\n` (com o cabeçalho
     de comentário `# managed by linkguard`) — efeito imediato, sem esperar
     renovação.
  2. Garante idempotentemente a linha `supersede domain-name-servers
     127.0.0.1;` em `/etc/dhcp/dhclient.conf` — pra que futuras renovações
     de lease do `dhclient` nunca mais sobrescrevam com o DNS do provedor.
     (Trabalha *com* o dhclient, não contra — mais idiomático que o bit
     imutável.)
- **Assunção documentada:** neste appliance o unbound é sempre o resolver
  (o backend DNS do `internal/netsvc` é sempre Kea+unbound, sem toggle pra
  desligar). `127.0.0.1` é sempre a intenção correta.
- **Deploy:** `deploy/linkguard-fw.service` ganha `/etc/resolv.conf` e
  `/etc/dhcp` no `ReadWritePaths=` (o `ProtectSystem=strict` bloqueia a
  escrita senão — mesmo padrão da adição de `/etc/systemd/network` e
  `/etc/chrony/conf.d` feitas antes nesta sessão).
- **Nota de migração:** quando a produção migrar pra `systemd-networkd`
  (Fase B, futura), o mecanismo do `resolv.conf` é revisitado (networkd usa
  `systemd-resolved` ou o próprio `.network`); o `EnsureResolvConf` continua
  válido enquanto o box usar ifupdown+dhclient.

## 5. Vigias de deriva de configuração (o coração do pedido)

Novos health-checks em `internal/monitoring`, seguindo o padrão já existente
(`ensureMeta(key, name, category)` + `observe` + par de alertas
`ok`/`problema` como `NTPSynced`/`NTPUnsynced`), que **comparam o aplicado
com a realidade viva** — a dimensão de que o painel é cego hoje:

- **`firewall-nat`**: a regra de masquerade viva
  (`nft list chain inet linkguard postrouting`) referencia exatamente as
  interfaces das WANs configuradas, **e** todas essas interfaces existem no
  kernel (`/sys/class/net/<iface>`). Vermelho + alerta se referenciar uma
  interface inexistente, ou se divergir do conjunto de WANs configuradas.
- **`wan-interface`**: cada Link WAN aponta pra uma interface que existe no
  kernel. Vermelho + alerta nominal ("WAN VIVO configurada em enp4s0, que
  não existe") se não. **Este é o vigia que teria pego o incidente de hoje
  no instante do boot** — antes do operador precisar de qualquer SSH.
- **`dns-resolver`**: `/etc/resolv.conf` resolve pra `127.0.0.1`. Vermelho +
  alerta se aponta pra outra coisa (ex.: dhclient sobrescreveu).

Cada um vira um item no painel `SystemHealth` e um par de `AlertType` novos
(mesma mecânica dos alertas já existentes, com auto-resolução na volta ao
normal). Nenhum dado falso: se a informação necessária pra checar não
estiver disponível (ex.: tabela nftables ausente), o item reporta
degradado/desconhecido, não "ok" otimista.

## 6. Camadas — como isso se encaixa com o que já existe

| Camada | O que resolve | Estado |
|---|---|---|
| Nomeação estável por MAC (Fase A) | Nome de interface nunca muda → Link nunca fica stale por rename de hardware | **Código pronto, falta aplicar+reboot em produção** (ação operacional recomendada, fora desta spec) |
| Reconciliar NAT + resolv.conf no boot (esta spec §3–4) | Estado aplicado sempre re-derivado da fonte de verdade, mesmo que algo tenha mudado | Esta spec |
| Vigias de deriva (esta spec §5) | Quando qualquer coisa ainda diverge (por qualquer causa), o painel grita — sem SSH | Esta spec |

As três se complementam: a Fase A estanca a causa mais comum na fonte; a
reconciliação torna o sistema auto-corretivo pra deriva de qualquer origem;
os vigias tornam a deriva residual **visível no painel**, que é o pedido
central do operador.

## 7. Fora de escopo (explicitamente)

- **Auto-curar `links.interface` por MAC** quando a interface configurada
  some mas outra com o mesmo MAC aparece: é conceitualmente a nomeação
  estável por MAC (Fase A, já implementada). O vigia `wan-interface` desta
  spec **detecta e avisa**; auto-curar o registro do Link é evolução futura
  que se sobrepõe à Fase A.
- **Migração ifupdown→networkd** (Fase B) — inalterada, futura.
- **Remover a regra iptables manual de emergência** — limpeza operacional,
  não código.

## 8. Testes e verificação

- **Backend (TDD real):** `ReconcileMasquerade` reconstrói a regra a partir
  de N WANs, é idempotente, sanitiza nomes; `EnsureResolvConf` escreve
  127.0.0.1 + insere o `supersede` idempotentemente (não duplica em segunda
  execução), no-op em dry-run; cada health-check retorna
  ok/degradado/problema pros casos: interface existe vs não existe, regra
  bate vs diverge, resolv.conf 127.0.0.1 vs provedor. Fakes dedicados por
  comando (não reaproveitar `fakeNftExec` genérico — lição desta sessão:
  parsers quebram com `""`).
- **Integração na VM de teste** (`~/linkguard-testvm/`): subir, renomear uma
  interface à força (ou apontar um Link pra interface inexistente), reiniciar
  o serviço, confirmar que (a) a reconciliação corrige/loga, e (b) o painel
  de saúde acende o vigia correto. Simular o dhclient sobrescrevendo
  `resolv.conf` e confirmar que o `supersede` + re-escrita corrige.
- **Produção:** só depois de verde na VM; o deploy em si é seguro (as
  reconciliações são idempotentes e os vigias são read-only), mas a
  aplicação da Fase A + reboot é janela à parte.
