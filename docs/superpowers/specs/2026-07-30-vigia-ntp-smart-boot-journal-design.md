# Vigia: NTP, SMART, boot lento e journal corrompido — Design

## Contexto

O servidor de produção (Dell OptiPlex 3010, disco mecânico) sofreu sua primeira queda de
energia real. A investigação pós-fato (via `journalctl`/`dmesg`/`systemd-analyze`, à mão via
SSH) revelou:

1. **Nenhum client NTP rodando** — nem `systemd-timesyncd` nem `chrony`. O relógio aguentou
   essa queda porque a bateria do RTC está boa, mas não há correção automática se um dia
   driftar.
2. O disco (Seagate Barracuda de 2013) é peça mecânica única — ponto de falha que hoje não é
   monitorado (`smartmontools` está instalado na máquina, mas o LinkGuard não lê o status).
3. O boot demorou ~4 minutos (majoritariamente recuperação de journal do ext4 pós-desligamento
   sujo), sem nenhum sinal automático — precisei investigar manualmente.
4. `journalctl --verify` achou um arquivo de journal antigo corrompido.

Este spec estende a feature "Vigia" já existente (monitoramento zero-config de serviços
systemd/disco/WAN/próprio linkguard-fw, com alertas por transição+anti-flap, painel "Saúde do
sistema" no Dashboard) com 4 checks novos, cobrindo os 4 achados acima. Design completo do
Vigia original: `docs/superpowers/specs/2026-07-02-vigia-monitoring-alerts-design.md`.

## Por que isso cabe dentro do Vigia (não é um sub-projeto novo)

O motor de transição+anti-flap (`Collector.observe(key, up bool, now int64) transition`, em
`internal/monitoring/healthchecks.go`) já é genérico — qualquer novo check só precisa reduzir
seu resultado a um booleano "up" por chamada e ganha de graça: dedupe de alerta, anti-flap (2
leituras "down" consecutivas antes de declarar queda), e aparecer no painel "Saúde do sistema"
sem nenhuma tela nova (o painel é uma grade genérica de tiles por item, ver
`web/src/components/SystemHealth.tsx`). O par de alertas (`TypeX`/`XDown()`/`XUp()` em
`internal/alerts/service.go`) e o toggle mestre `cfg.Enabled` (settings key `"monitoring"`,
interruptor único — ligar/desligar TUDO de uma vez, decisão de produto já tomada e documentada
no spec original) também já existem e não mudam.

## Arquitetura

### 1. NTP — LinkGuard assume a configuração (não só monitora)

Novo pacote pequeno `internal/timesync/timesync.go`, seguindo o mesmo padrão de
`routes.EnsureForwarding()`/`hosttraffic.EnsureAccounting()` ("LinkGuard é dono deste
pré-requisito de runtime"):

- `EnsureEnabled(ctx, exec firewall.Executor)`: verifica se a unidade `chrony.service` existe
  (`systemctl list-unit-files --no-legend chrony.service`, via `ExecuteRead` — leitura). Se
  existir e não estiver habilitada/ativa, roda `systemctl enable --now chrony` via `Execute`
  (respeita dry-run, como toda mutação no projeto). Se a unidade NÃO existir (chrony não
  instalado), loga um aviso e não faz nada — **o LinkGuard não roda `apt install` sozinho**:
  instalar pacote novo via gerenciador de pacotes de dentro do binário é uma categoria de risco
  diferente de habilitar um serviço já presente (trava de apt concorrente, unattended-upgrades,
  etc.), e está fora do escopo deste projeto. O `.deb` ganha `chrony` como `Recommends` (mesmo
  nível que `kea-dhcp-server`/`unbound` hoje, em `.github/workflows/release.yml`) — numa
  instalação nova ele já vem junto; se não vier (como nesta máquina específica até o próximo
  `dpkg -i`), o Vigia relata "não sincronizado" e cabe ao admin instalar manualmente.
- `IsSynced(ctx, exec) bool`: lê `timedatectl show --property=NTPSynchronized --value`,
  retorna `true` se a saída for `"yes"`.
- Chamado em `main.go` junto das outras `Ensure*` (`timesync.EnsureEnabled(ctx, exec)`, mesmo
  bloco de `routeSvc.EnsureForwarding()`/`trafficSvc.EnsureAccounting()`).

Novo check em `internal/monitoring/healthchecks.go`, `checkNTP(cfg)`, seguindo exatamente o
formato de `checkServices`: `up := timesync.IsSynced(ctx, c.exec)`, `key := "ntp:sync"`,
`c.observe(key, up, now)` + `c.ensureMeta(key, "ntp-sync", "resource")`, alertas
`TypeNTPUnsynced`/`NTPUnsynced()`/`NTPSynced()` (severidade **Aviso** — não é uma queda de
serviço, é uma degradação silenciosa).

### 2. SMART do disco — três sinais, um pacote de leitura

Novo pacote `internal/disksmart/disksmart.go`:

- `DetectRootDisk(ctx, exec) (string, error)`: descobre o dispositivo de bloco por trás do
  filesystem raiz (`findmnt -no SOURCE /`, remove sufixo de partição — ex. `/dev/sda2` →
  `/dev/sda`) — nunca hardcoded, mesma filosofia dos parsers de interface/rota já existentes no
  projeto (nunca assumir, sempre derivar do estado real do sistema).
- `Read(ctx, exec, device string) (Report, error)`: roda `smartctl -x -j <device>` (saída JSON,
  parseada com `encoding/json` — muito mais confiável que regex sobre tabela de texto, e
  `smartctl` já suporta isso nativamente). `Report{ Passed bool; ReallocatedSectors int;
  TemperatureC int }`.

Três checks novos em `healthchecks.go`, todos alimentados por uma única chamada a
`disksmart.Read` por tick (evita rodar `smartctl` três vezes seguidas):

- `smart:health` — `up = report.Passed`. Alertas `TypeDiskSMARTFail`/`DiskSMARTFail()` (**Crítico**
  — disco reportando falha via SMART é sério) `/DiskSMARTOK()`.
- `smart:realloc` — `up = report.ReallocatedSectors <= cfg.SMARTReallocatedThreshold` (novo
  campo em `monitoring.Config`, padrão `0` — este disco está em 0 hoje, então qualquer aumento já
  é sinal). Alertas `TypeDiskSMARTDegraded`/`DiskSMARTDegraded()`/`DiskSMARTNormal()`
  (**Aviso**).
- `smart:temp` — `up = report.TemperatureC <= cfg.SMARTTempThresholdC` (novo campo, padrão
  `55`). Par de alertas próprio, `TypeDiskSMARTHot`/`DiskSMARTHot()`/`DiskSMARTCool()`
  (**Aviso**) — dedicado, não reaproveita o par de `smart:realloc`: são sinais de degradação
  semanticamente diferentes (temperatura é ambiental/transiente, setor realocado é dano
  permanente), e o resto do projeto já segue essa granularidade (`HighCPU`/`HighMemory`/
  `DiskFull` são três alertas distintos, não um "recurso sob pressão" genérico). Texto do
  alerta cita o valor medido, como já é o padrão de `DiskFull`.

Os três valores (passed como 0/1, setores realocados, temperatura) são gravados no `tsdb` via
`c.rec.Gauge("smart.reallocated", "", float64(n))` e `c.rec.Gauge("smart.temp_c", "",
float64(t))` a cada tick — novo prefixo `"smart.": 30` em `internal/tsdb/schema.go`'s
`nativeSteps` (mesma cadência de `sys.*`), para existir histórico/tendência mesmo sem gráfico
dedicado ainda.

### 3. Boot lento — métrica é "tempo até o LinkGuard ficar pronto", não "tempo até o systemd terminar"

Descartei usar `systemd-analyze` diretamente: ele só fecha depois que TODO o sistema termina de
subir, incluindo cadeias de serviço que não têm nada a ver com o LinkGuard (ex.: a infra
Samba/AD-DC já existente na máquina, que hoje sozinha atrasa uns bons segundos o boot completo).
O que importa de verdade é quanto tempo o painel demorou pra ficar acessível.

No primeiro tick do `Collector` (uma vez só, guardado por um campo booleano — não faz sentido
reavaliar a cada 30s, já que `/proc/uptime` só cresce), lê `/proc/uptime` (primeiro campo =
segundos desde o boot do kernel) no momento em que o `collect()` roda pela primeira vez. Compara
contra `cfg.BootTimeThresholdSec` (novo campo, padrão `180` = 3 minutos, configurável). Se
exceder, é um evento único por boot — não um estado contínuo — mas ainda passa por
`c.observe("boot:time", dentroDoLimite, now)` pra reaproveitar o mesmo mecanismo de alerta e
aparecer no painel (o item simplesmente nunca muda de estado de novo depois da primeira leitura,
o que o modelo de `observe()` já suporta sem alteração). Alertas
`TypeSlowBoot`/`SlowBoot(segundos)`/nenhuma recuperação automática correspondente faz sentido
aqui (não existe "boot voltou ao normal" — só o próximo boot é que pode ser rápido de novo) —
**este é o único dos 4 checks que não segue o par completo down/up**: só dispara `SlowBoot` uma
vez se ultrapassar o limite, sem contraparte de recuperação (ver Casos de borda abaixo). Grava
`c.rec.Gauge("boot.seconds", "", duração)` uma vez por boot (novo prefixo `"boot.": 3600` em
`nativeSteps`, já que é uma amostra isolada, não uma série contínua) — histórico consultável
mesmo sem gráfico dedicado.

### 4. Journal corrompido — agendador próprio, semanal, fora do loop de 30s

`journalctl --verify` é pesado no disco desta máquina (visto na investigação levar dezenas de
segundos) — não roda dentro do `collect()` de 30s (bloquearia CPU/mem/disco/serviços por tempo
demais naquele tick). Novo arquivo `internal/monitoring/journalcheck.go`, replicando a forma já
revisada e comprovada de `internal/backup/scheduler.go`: um tipo `JournalScheduler` com seu
próprio ticker (`tickInterval = 1 * time.Hour`, mesmo valor do backup — granularidade grossa o
suficiente pra resolver "semanal" sem precisar de cron real), `Run(ctx)` chamando `maybeRun`
a cada hora, que só executa de fato se já passou `cfg.JournalVerifyIntervalDays` (novo campo,
padrão `7`) desde a última verificação (timestamp persistido em settings, mesmo padrão de
`backup_last_run`). `RunOnce(ctx)` roda `journalctl --verify` via `ExecuteRead`, procura linhas
`FAIL:` na saída, e chama `alerts.JournalCorrupt(detalhe)` (**Aviso** — degrada
observabilidade, não é uma queda operacional) se achar alguma, ou `alerts.JournalOK()` caso a
última verificação tivesse achado corrupção e esta não ache mais (journal antigo rotacionado
"cura" o problema sozinho com o tempo). Wired em `main.go` junto de `go backupSched.Run(ctx)`:
`go journalSched.Run(ctx)`.

## Configuração nova (`monitoring.Config`)

Todos os campos novos entram debaixo do mesmo `cfg.Enabled` — sem toggle novo, mesma decisão de
produto do Vigia original (um interruptor só). Só visíveis no modo Avançado da tela de
Configurações → Monitoramento, mesmo padrão de `Services`/`DiskThresholdPct` hoje:

```go
type Config struct {
    Enabled                   bool     `json:"enabled"`
    Services                  []string `json:"services"`
    DiskThresholdPct          int      `json:"disk_threshold_pct"`
    SMARTReallocatedThreshold int      `json:"smart_reallocated_threshold"` // default 0
    SMARTTempThresholdC       int      `json:"smart_temp_threshold_c"`      // default 55
    BootTimeThresholdSec      int      `json:"boot_time_threshold_sec"`     // default 180
    JournalVerifyIntervalDays int      `json:"journal_verify_interval_days"` // default 7
}
```

Compatibilidade: `LoadConfig` já usa `c := defaults(); json.Unmarshal(raw, &c)` — configs
salvas antes desta feature simplesmente não têm essas chaves no JSON, e `Unmarshal` não zera
campos ausentes, então eles ficam nos valores de `defaults()`. Nenhuma migração necessária.

## Frontend

Nenhuma tela nova. `web/src/components/SystemHealth.tsx`'s mapa `LABEL` ganha 6 entradas novas
(`ntp-sync` → "Sincronização de horário", `smart-health` → "Disco (SMART)", etc.).
`web/src/components/MonitoringSettings.tsx` ganha os 4 campos novos de threshold no bloco
"Avançado", mesmo padrão dos campos existentes. `web/src/types/index.ts`'s `MonitoringConfig`
ganha os 4 campos correspondentes.

Os tiles do painel usam o texto genérico "no ar"/"fora do ar" já existente — não ganham texto de
status customizado por tipo (ex. "boot lento" continua aparecendo como tile vermelho "fora do
ar", não uma frase própria). É uma simplificação deliberada: manter o painel 100% genérico por
`kind` evita crescer um sistema de templates de texto por tipo de check só para 4 casos. Se
depois de usar isso na prática achar confuso, é um ajuste pontual e barato de fazer depois.

## `.deb`: novas dependências recomendadas

`Recommends` em `.github/workflows/release.yml` (fonte da verdade do control file) ganha
`smartmontools` (pro `smartctl`) e `chrony`, ao lado de `kea-dhcp-server, unbound` já
existentes. Continuam `Recommends`, não `Depends` — não bloqueiam `dpkg -i` numa máquina sem
apt resolvendo dependências (mesmo raciocínio já usado pros dois pacotes existentes).

## Casos de borda

- **NTP sem internet**: se as duas WANs estiverem fora do ar, `chrony` nunca sincroniza —
  correto alertar (o operador precisa saber que o relógio pode estar driftando).
- **`smartctl` não instalado** (chrony ausente, mesmo raciocínio): `disksmart.Read` retorna
  erro; o check trata erro de leitura como "não sei o estado" e não chama `observe()` naquele
  tick (mesmo padrão que `checkServices`'s tratamento de erro de leitura de sistema já
  implicitamente segue) — não gera alerta de "SMART falhou" por engano quando na verdade é só
  a ferramenta que está ausente. Evolução futura possível: um alerta específico "ferramenta
  SMART ausente", fora de escopo aqui.
- **Boot lento sem recuperação automática**: como não existe transição "up" natural pra esse
  check (o processo já está rodando, o boot já aconteceu), o item fica permanentemente
  "down" no painel pelo resto daquela execução do processo se o boot foi lento — o próximo
  reboot (novo processo, novo primeiro tick) reavalia do zero. Isso é o comportamento correto:
  não tem como "curar" um boot que já aconteceu.
- **Journal verify demorado demais**: usa o mesmo `Timeout` padrão do `RealExecutor` (30s) —
  se `journalctl --verify` nesta máquina específica demorar mais que isso (viável, o disco é
  lento e o journal é grande), a chamada falha por timeout. Isso é aceitável para uma checagem
  semanal best-effort (tenta de novo na próxima semana), mas vale registrar como risco
  conhecido — se acontecer na prática, aumentar o timeout desse `ExecuteRead` específico é o
  ajuste natural.

## Testes

Sem framework de teste automatizado que rode contra hardware real (óbvio — não dá pra testar
"disco falhando" de verdade). Segue o padrão já estabelecido no projeto: cada função que chama
`exec` é testada injetando um executor falso (mesmo padrão de
`routes.forwarding_test.go`/`hosttraffic.service_test.go`) que retorna saídas canned de
`smartctl -x -j`, `timedatectl show`, `journalctl --verify`, `findmnt`, cobrindo os casos
felizes e de erro/ausência de ferramenta. `checkNTP`/os três checks de SMART/`checkResource`
reaproveitam a suíte de testes já existente pra `observe()`/anti-flap (não precisa reescrever
esses testes, só confirmar que os novos checks os alimentam corretamente). Verificação final via
`go build ./...` + `go test ./...` (padrão do projeto), mais teste manual em produção depois do
deploy (não dá pra simular queda de energia real num teste automatizado).

## Fora de escopo (explicitamente)

- LinkGuard não instala pacotes via `apt` — só habilita o que já está presente.
- Sem comparação de boot-time contra média histórica (decisão já tomada: limite fixo
  configurável).
- Sem gráfico dedicado de tendência SMART/boot na UI — só o histórico no `tsdb`, consultável no
  futuro se for pedido.
- Sem granularidade de toggle por-tipo-de-check — tudo debaixo do interruptor mestre existente.
- Sem alerta de "ferramenta SMART/chrony ausente" dedicado (só o efeito indireto: sem a
  ferramenta, o check correspondente nunca fica "up").
