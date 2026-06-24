# LinkGuard FW — Roadmap de Funcionalidades

## Visão

Transformar a operação manual de firewall/roteamento (hoje feita à mão em
`/etc/network/firewall.sh`) numa **plataforma gerenciada, multi-administrador e
host-cêntrica** para pequenas e médias empresas com múltiplos links WAN.

O norte é: **tudo que hoje é uma linha de bash frágil deve virar uma ação
declarativa, auditável e reversível no painel.**

### Quem usa
PMEs com múltiplos administradores. Cada admin precisa de credencial própria e
permissão por funcionalidade (RBAC), com registro de "quem fez o quê".

---

## Princípio central

> Quase toda funcionalidade nova depende de **UMA fundação**:
> **inventário de hosts da LAN + contabilização de tráfego por host.**

Resolvido isso, caem de graça: identificar hosts, medir consumo, bloquear,
agrupar e direcionar por WAN. DHCP/DNS **não** são pré-requisito para isso —
o firewall já vê todo o tráfego forwarded. Eles entram depois, como
enriquecimento (nome legível, MAC, reserva estática).

---

## Decisões transversais (fundação)

### F1 — nftables nativo, declarativo e idempotente
O backend do kernel já é nftables (Debian 13). A mudança é trocar o frontend
imperativo (`iptables -A ...` append-only) por **geração de ruleset `nft`
declarativo**, aplicado de forma atômica (flush+load). Benefícios diretos:
- acaba a duplicação de regras ao reaplicar (problema real hoje);
- `map` saddr→mark resolve "grupo de host → WAN" em uma regra;
- `set` nomeado resolve "bloquear/desbloquear host" sem recarregar nada.

### F2 — RBAC multi-admin
Hoje a auth é single-user (`admin/admin` + JWT). Evoluir para:
- usuários, papéis e permissão por funcionalidade (ex.: quem pode mexer em
  WAN/rotas vs. quem só vê relatórios);
- todo comando de escrita checa permissão e grava **quem** no audit log;
- avaliar integração com AD/Samba (o servidor já roda `winbind`) como opção
  futura de autenticação.

### F3 — Identidade + contabilização de host
- **Identidade**: `ip neigh` (IP↔MAC) + leases DHCP (hostname) + conntrack.
- **Contabilização**: ligar `net.netfilter.nf_conntrack_acct=1` e/ou
  contadores nft por host; agregar com *rollup* temporal.

### F4 — Armazenamento
- **Manter SQLite** para config/estado (links, regras, grupos, hosts, usuários,
  alertas). Trocar por Postgres mataria a vantagem de "binário único, drop-in".
- O dado que escala é **série temporal por host**. Resolver com *downsampling*
  estilo RRD (1s→1min→1h→1dia), estendendo o `internal/trafficrrd` já existente
  para a dimensão por host/grupo. **Não** jogar série temporal crua no banco.

---

## Fases

### Fase 0 — Saneamento do que já existe
Importar e corrigir o setup atual antes de adicionar features.
- [ ] Importar `firewall.sh` para o modelo declarativo do LinkGuard.
- [ ] Eliminar regras/`ip rule` duplicadas (causadas pelo append-only).
- [ ] Unificar persistência (hoje há `netfilter-persistent` **e** `rc.local` —
      escolher uma fonte de verdade: o LinkGuard).
- [ ] Escopar o `MASQUERADE` por interface WAN (hoje é global, sem `-o`).
- [ ] Remover linha morta `ip rule add 192.168.18.1 from sumicity`.

### Fase 1 — Firewall básico em 1 clique
Para máquinas que querem virar firewall "do zero".
- [ ] Habilitar `ip_forward` + NAT (MASQUERADE) escopado por WAN.
- [ ] Política FORWARD sã por padrão.
- [ ] **Grupos de regras via chains nativas** (nft chains) — ativar/desativar um
      grupo inteiro removendo/inserindo o jump, sem mexer regra a regra.

### Fase 2 — Host-cêntrico (a fundação que destrava o resto)
- [ ] Inventário de hosts da LAN trafegando dados (ip neigh + conntrack).
- [ ] Consumo de rede por host (conntrack acct → rollup RRD por host).
- [ ] **Bloquear host em 1 clique** (named set nft; add/remove atômico).

### Fase 3 — Grupos de host → WAN
Produtiza as linhas `mangle MARK` que hoje são editadas na mão.
- [ ] Criar grupos de host e atribuir a uma WAN (fwmark → tabela de rota).
- [ ] Implementar como `map` nft saddr→mark (uma regra, N hosts).
- [ ] **Identificar por MAC/reserva**, não por IP solto (ver Fase 5) — hoje o
      pin por IP dentro do range DHCP dinâmico é frágil.

### Fase 4 — Rebalanceamento agendado (requisito do cliente)
Mover hosts pesados para o link de maior capacidade — **sem** automação em
tempo real (que quebraria conexões ativas).
- [ ] Política configurável pelo admin (limiares, qual WAN é "a maior").
- [ ] Execução **agendada** (ex.: madrugada ou 2x/dia), janela de poucas conexões.
- [ ] **Preview / dry-run** antes de aplicar; aplicar = repinagem determinística.
- [ ] Modo "sugerir e aprovar com 1 clique" como alternativa ao automático.

### Fase 5 — Absorver DHCP e DNS (serviços que já são operados na mão)
O servidor já roda `isc-dhcp-server` + `bind9`. Trazer pro painel.
- [ ] **DHCP**: migrar `isc-dhcp` (EOL) → avaliar **Kea** (tem API REST de
      controle, ideal para painel) vs. dnsmasq. Reservas estáticas por MAC
      consertam o pin de WAN por host.
- [ ] **DNS**: log de queries por host (visibilidade) + filtro opcional por
      blocklist. **DNS não é enforcement** — o bloqueio real continua no firewall.

---

## Não-faça / armadilhas

- **Não** auto-balancear hosts em tempo real → quebra conexões (NAT preso ao IP
  da WAN). Só agendado ou só para fluxos novos.
- **Não** trocar SQLite por Postgres → mata o "binário único". Escala de métrica
  se resolve com rollup, não com outro banco.
- **Não** tratar DNS como controle de acesso → burlável com DoH/DNS fixo.
- **Não** fixar host em WAN por IP dentro de range DHCP dinâmico → use MAC/reserva.

---

## Decisões pendentes (precisam de definição)

1. **DHCP**: Kea (API-first, recomendado) vs. dnsmasq (DHCP+DNS num daemon só)?
2. **Autenticação de admin**: local (no SQLite) apenas, ou também via AD/winbind?
3. **Escopo do nftables**: migrar tudo de uma vez ou conviver com as regras
   legadas durante a transição?
