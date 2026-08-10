# Controle de NTP no LinkGuard FW

## 1. Motivação

Hoje o LinkGuard só *observa* passivamente a sincronização de horário:
`internal/timesync.EnsureEnabled` liga o `chrony` no boot **se ele já
estiver instalado** (nunca instala o pacote), e `internal/timesync.IsSynced`
alimenta um health-check (`internal/monitoring/healthchecks.go`,
`checkNTP`) que dispara os alertas `ntp_unsynced`/`ntp_synced` (feature
"Vigia", já em produção). Não existe nenhuma tela no painel — nem status
visível, nem forma de trocar servidor NTP, nem de mexer no fuso horário.

Pedido do usuário (2026-08-10): dar ao LinkGuard controle real disso — ver
status, configurar servidores customizados, instalar o `chrony` se não
estiver presente, e controlar o fuso horário — tudo pelo painel, sem
precisar de SSH.

**Fora do escopo desta spec** (não pedido, não investigado a fundo): a
investigação do "relógio errado no dashboard" que motivou a conversa
concluiu que não há bug de código — o clock exibido no painel vem do
navegador (`Dashboard.tsx`), e o fuso/sincronização do servidor de produção
já estavam corretos no momento da investigação. O mais provável é que
alguns alertas tenham sido gravados com timestamp errado durante a janela
de rede instável logo após a reinstalação do disco (boot 01:37, chrony só
selecionou fonte às 02:29). Nada a corrigir em código por causa disso.

## 2. Arquitetura

Mesmo padrão já estabelecido por `internal/netsvc`/`internal/keaunbound`
(DHCP/DNS): um `Config` persistido como JSON na tabela genérica de settings
(sem tabela nova), uma página própria no painel (`Ntp.tsx`, mesmo padrão de
`Dhcp.tsx`/`Dns.tsx` — não dentro de `Settings.tsx`, que é só
About/Geral/Retenção), com o fluxo "salvar aplica sozinho" via debounce
(`autoApplier`, `autoApplyDelay = 1500ms`).

`internal/timesync` cresce de 2 funções (44 linhas) pra um pacote completo
com `Config`, geração/aplicação de config do chrony, e status detalhado.
**`IsSynced` e `EnsureEnabled` continuam exatamente como estão hoje, sem
nenhuma mudança de assinatura ou comportamento** — o `checkNTP`/alertas
Vigia continuam sendo a única fonte de verdade pra status de sincronização;
a tela nova só *reusa* `IsSynced` pra exibir, nunca duplica a lógica de
detecção.

## 3. Config

```go
type Config struct {
    Servers  []string `json:"servers"`  // vazio = usa o pool padrão do Debian, LinkGuard não toca em nada
    Timezone string   `json:"timezone"` // vazio = não mexe no fuso já configurado no SO
}
```

Persistido via `db.SetSetting`/`db.GetSetting` (mesma tabela KV genérica que
`netsvc`), chave `ntp_config`. `DefaultConfig()` retorna `Config{}` (tudo
vazio) — estado inicial é "não gerenciado", idêntico ao comportamento atual
(`EnsureEnabled` já liga o `chrony` com a config padrão do Debian).

## 4. Aplicar servidores customizados

Debian já ships `/etc/chrony/chrony.conf` com a linha
`confdir /etc/chrony/conf.d` — um diretório de drop-in oficialmente suportado
pelo `chronyd`. **O LinkGuard nunca toca no `chrony.conf` do pacote** (ao
contrário de `kea-dhcp4.conf`/`unbound.conf`, que o LinkGuard possui
inteiramente) — só escreve/remove um arquivo próprio,
`/etc/chrony/conf.d/linkguard.conf`, com o cabeçalho `# managed by
linkguard` e uma linha `server <host> iburst` por servidor configurado.

Reconciliação idêntica ao padrão recém-implementado pra arquivos `.link`
(Fase A de nomeação de interface): se `Config.Servers` estiver vazio, o
arquivo é **removido** (se existir) — volta pro pool padrão do Debian, sem
deixar lixo. Se não estiver vazio, o arquivo é (re)escrito por completo.

```go
func (s *Service) ReloadConfig(ctx context.Context) error {
    // grava/remove /etc/chrony/conf.d/linkguard.conf conforme Config.Servers
    // (vazio => remove; não vazio => escreve, sobrescrevendo o anterior)
    // depois: systemctl reload-or-restart chrony (mesmo padrão do keaunbound —
    // reload se o unit suportar, senão restart; nunca full-stop)
}
```

## 5. Fuso horário

`Config.Timezone` vazio = não mexe (deixa o que o SO já tem configurado —
já está correto na produção hoje, `America/Sao_Paulo`). Se setado, aplica
via `timedatectl set-timezone <tz>` — efeito **imediato**, sem reboot
(diferente da nomeação de interface por MAC). Validação: `timedatectl
list-timezones` pra popular as opções no frontend como um `<select>`, não
um campo de texto livre (evita erro de digitação gerando um fuso inválido).

## 6. Status exibido (somente leitura)

Reusa `timesync.IsSynced` (já existe) e acrescenta uma nova função de
leitura, `timesync.Status(ctx, exec) (StatusInfo, error)`, que roda
`chronyc tracking` e faz parse de `Stratum`, `System time` (offset), e
`Reference ID`/fonte selecionada — exibidos como texto informativo na nova
página, sem nenhuma lógica de alerta associada (isso continua 100% em
`checkNTP`).

## 7. Instalar o chrony (quando ausente)

Botão manual explícito no painel (nunca automático) — mesma decisão já
tomada nesta conversa: em vez do processo do LinkGuard rodar `apt-get
install` diretamente (o que exigiria afrouxar `ReadWritePaths=` do
`ProtectSystem=strict` pra praticamente todo o filesystem de pacotes), ele
pede pro **systemd** rodar isso numa unit transiente própria, sem o
sandboxing do LinkGuard:

```go
func (s *Service) InstallChrony(ctx context.Context, exec firewall.Executor) error {
    _, err := exec.Execute(ctx, "systemd-run", "--pipe", "--wait",
        "--", "apt-get", "install", "-y", "--no-install-recommends", "chrony")
    return err
}
```

Isso é só uma chamada D-Bus pro PID 1 (mesma categoria da chamada já
existente `systemctl enable --now chrony`) — não precisa de nenhuma
permissão de escrita nova no unit do LinkGuard pra essa parte
especificamente. Depois de instalar, `EnsureEnabled` (já existente,
inalterado) garante que o serviço fica ligado no próximo boot.

## 8. Endpoints da API

Mesmo padrão de `internal/api/handlers/netsvc.go`. Segue a granularidade já
usada por DHCP/DNS (`internal/auth/permissions.go`: `PermDHCPRead/Write`,
`PermDNSRead/Write`) — NTP ganha seu próprio par dedicado em vez de
reusar o genérico `system.*`, permitindo conceder controle de NTP sem
liberar o resto de "Sistema" (retenção, aliases):

```go
PermNTPRead  Permission = "ntp.read"
PermNTPWrite Permission = "ntp.write"
```

- `GET /api/ntp` — `Config` atual + `StatusInfo` (sincronizado, stratum,
  offset, fonte) num só payload, permissão `PermNTPRead`.
- `PUT /api/ntp` — atualiza `Config`, dispara auto-apply debounced (mesmo
  `autoApplier` da netsvc), permissão `PermNTPWrite`.
- `POST /api/ntp/apply` — força aplicação imediata ("Aplicar agora"), mesmo
  padrão do botão manual de DHCP/DNS, permissão `PermNTPWrite`.
- `POST /api/ntp/install-chrony` — só existe/só habilitado no frontend
  quando o status indica chrony ausente; chama `InstallChrony` (§7),
  permissão `PermNTPWrite`.

## 9. Frontend

Página nova `web/src/pages/Ntp.tsx`, mesma estrutura de `Dns.tsx`: painel
de status (somente leitura) no topo, painel de configuração (lista de
servidores editável, seletor de fuso horário) com botão "Salvar" +
"Aplicar agora", e — condicionalmente, só se `chrony_installed: false` no
status — um painel de aviso com o botão "Instalar chrony".

## 10. Deploy

`deploy/linkguard-fw.service`: adiciona `/etc/chrony/conf.d` ao
`ReadWritePaths=` existente (mesmo padrão da adição de
`/etc/systemd/network` feita hoje mais cedo nesta sessão). Nenhuma outra
mudança de hardening — a instalação do pacote (§7) não precisa de
`ReadWritePaths` porque roda fora do sandbox do LinkGuard.

## 11. Testes

- `internal/timesync`: TDD real — geração do `linkguard.conf` a partir de
  `Config.Servers`, reconciliação (arquivo removido quando `Servers` fica
  vazio, sobrescrito quando muda), parse de `chronyc tracking` com uma
  amostra real de saída, `EnsureEnabled`/`IsSynced` permanecem cobertos
  pelos testes já existentes sem alteração.
- `internal/api/handlers`: os 4 endpoints, incluindo o caso "chrony não
  instalado" retornando o status correto.
- Frontend: `npm run build` limpo; verificação manual na VM de teste
  (mesmo `~/linkguard-testvm/`) cobrindo: chrony ausente → botão instalar
  aparece → instala → reaparece configurável; configurar servidor
  customizado → confirma `/etc/chrony/conf.d/linkguard.conf` no disco;
  limpar servidores → confirma arquivo removido; trocar timezone → confirma
  `timedatectl status` muda imediatamente.

## 12. Fora de escopo

- Autenticação NTP (chaves/NTS) — não pedido, complexidade desnecessária
  pra uma rede LAN interna.
- Servir NTP para a LAN (o LinkGuard virar um servidor NTP local pros
  clientes) — só consome/sincroniza, não foi pedido que sirva.
- Qualquer mudança no alerta Vigia (`ntp_unsynced`/`ntp_synced`) ou no
  health-check `checkNTP` — permanecem exatamente como estão.
