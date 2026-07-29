# Backup cifrado + envio periódico por e-mail

**Data:** 2026-07-29
**Status:** aprovado

---

## 1. Motivação

`GET /api/backup` já existe (`internal/api/handlers/backup.go`) e exporta um JSON com configurações,
links, reservas de DHCP e blocklist de DNS. Segredos (senha SMTP, tokens, chaves WireGuard) já ficam
numa tabela separada (`internal/secrets`) e nunca entram nesse export — isso não muda. Mas o que sobra
ainda é reconhecimento valioso pra quem for atacar a rede se o arquivo vazar: subnet CIDR, gateway,
nomes de interface, links WAN, e o inventário de hosts da LAN (MAC/IP/hostname de cada reserva DHCP).

Hoje esse arquivo só existe se o admin clicar em "Baixar backup" manualmente — não há cópia
automática fora do servidor. Se o disco morrer sem um backup recente, a configuração se perde.

Este spec cobre duas coisas juntas, porque a segunda só é seguro fazer com a primeira:
1. **Backup automático agendado**, enviado por e-mail (reaproveita o SMTP já configurado em
   Configurações → Notificações).
2. **Criptografia do arquivo de backup**, nos dois fluxos (manual e automático) — porque um arquivo
   que sai do servidor sozinho, por e-mail, é o cenário exato em que "vazou" deixa de ser hipotético.

## 2. Criptografia

### 2.1 Algoritmo e formato do arquivo

AES-256-GCM. Chave derivada de uma senha via **scrypt** (N=32768, r=8, p=1 — parâmetros do
`golang.org/x/crypto/scrypt` recomendados pra uso interativo/2026), com salt aleatório de 16 bytes
gerado por arquivo (nunca reaproveitado — armazenado junto do arquivo, não é segredo).
`golang.org/x/crypto` já é dependência direta do projeto hoje (`bcrypt` em `internal/auth`,
`curve25519` em `internal/wireguard`) — usar `scrypt` do mesmo módulo não adiciona dependência nova
ao `go.mod`.

Formato binário do arquivo cifrado:

```
offset  tamanho  campo
0       4        magic bytes: "LGB1" (LinkGuard Backup, versão 1)
4       16       salt (scrypt)
20      12       nonce (GCM)
32      N        ciphertext (inclui o tag de autenticação do GCM, últimos 16 bytes)
```

O byte de versão embutido no magic (`LGB1`) permite trocar o algoritmo no futuro sem quebrar leitura
de arquivos antigos — `Decrypt` rejeita magic desconhecido com erro claro em vez de tentar decifrar
lixo.

GCM garante integridade: um arquivo adulterado ou uma senha errada falham a decifrar (erro), nunca
decifram silenciosamente para dado incorreto.

### 2.2 Onde a senha fica guardada

Novo secret `backup_passphrase` no `internal/secrets` já existente (mesma tabela/chave-mestra que já
protege a senha SMTP, tokens de atualização e chaves WireGuard — `Set`/`Get`/`Status`/`Delete` já
prontos, nada novo a construir aqui). É necessária guardada porque o agendador cifra sozinho, sem
ninguém digitando senha na hora do envio automático.

**Modelo de ameaça, sem mudança em relação ao que já existe hoje**: protege contra um arquivo de
backup vazado, um `.db` copiado, um disco decomissionado. Não protege contra root na própria máquina
(que já lê o arquivo de chave e o banco) — mesmo texto de aviso que já existe no topo de
`internal/secrets/keyfile.go`.

### 2.3 Definir/trocar a senha

Novos endpoints em `BackupHandler`, mesmo padrão de outros secrets configuráveis pela UI (ex.:
`PUT /api/system/update/token` em `UpdateChecker.tsx`):

- `PUT /api/backup/passphrase` — body `{"passphrase": "..."}`. Valida `len(passphrase) >= 12`
  (backup carrega topologia de rede + inventário de hosts; 12 é mais alto que o mínimo de 8 usado pra
  senha de usuário porque aqui não há 2FA nem rate-limit de tentativa por trás — é a única barreira).
  Grava via `sec.Set("backup_passphrase", passphrase)`. Requer `system.write` (mesma permissão que já
  protege backup/restore).
- `GET /api/backup/passphrase/status` — `{"configured": bool}`, via `sec.Status("backup_passphrase")`.
  Front usa isso pra decidir se mostra "Baixar backup"/liga o agendamento, ou pede pra configurar
  primeiro.
- **Trocar a senha não recifra backups antigos** — um backup cifrado com a senha anterior só abre com
  a senha anterior. Comportamento esperado, sem necessidade de histórico de chaves (YAGNI) — a UI só
  precisa deixar isso explícito no texto de ajuda ao lado do campo.

### 2.4 Export (manual e automático) — sempre cifrado

`GET /api/backup` deixa de devolver JSON puro: monta o `BackupData` (lógica de `snapshot()` inalterada),
serializa pra JSON internamente, cifra com a senha guardada e devolve os bytes binários do formato
`LGB1`. Se `backup_passphrase` não estiver configurado, `400` com mensagem clara — não dá pra exportar
sem senha definida.

Nome do arquivo/`Content-Disposition` muda de `linkguard-backup.json` para `linkguard-backup.lgbak`
(extensão nova, deixa claro que não é JSON legível direto).

### 2.5 Restore — sempre pede a senha

`POST /api/backup/restore` muda de contrato: hoje recebe o `BackupData` como JSON puro no corpo; passa
a receber `multipart/form-data` com dois campos — `file` (o `.lgbak`) e `passphrase` (string). O
handler decifra com a senha recebida no request (nunca assume a senha guardada localmente — ver
motivo abaixo), decodifica o JSON resultante como `BackupData`, e segue com a lógica de restore já
existente sem mudança (settings/reservas/blocklist, nunca usuários/papéis/links).

**Por que sempre pedir a senha, mesmo que já exista uma guardada nesta máquina**: o cenário principal
de restore é justamente recuperar um backup **noutra máquina** (a original morreu — é o motivo de
mandar o backup pra fora em primeiro lugar). Nesse caso a senha guardada na máquina nova (se houver
alguma, provavelmente recém-instalada e vazia) não tem por que ser a mesma que cifrou o arquivo. Pedir
sempre evita um comportamento "às vezes funciona sem perguntar, às vezes pede" — mais previsível.

Senha errada ou arquivo corrompido → `400` com mensagem "senha incorreta ou arquivo inválido" (GCM não
distingue as duas causas, e não faz sentido tentar: ambas terminam na mesma ação do usuário, conferir
a senha e o arquivo).

## 3. Backup automático agendado

### 3.1 Configuração

Novo setting `backup_schedule` (chave em `internal/storage`, mesmo mecanismo do
`traffic_retention_profile` já existente) com valores `off` (padrão) / `daily` / `weekly` / `monthly`.
Endpoints:

- `GET /api/backup/schedule` — `{"schedule": "off"}`
- `PUT /api/backup/schedule` — `{"schedule": "daily"}`. Rejeita com `400` se `backup_passphrase` não
  estiver configurado e o valor pedido não for `off` — não dá pra ligar o agendamento sem senha.

### 3.2 O agendador

Pacote novo `internal/backup/scheduler.go`, mesmo padrão de ticker do
`internal/monitoring/collector.go` (um `time.Ticker` de granularidade fixa — 1h é suficiente pra
resolver diário/semanal/mensal sem precisar de um cron real — que a cada disparo confere se já passou
o intervalo configurado desde o último envio bem-sucedido, usando o timestamp gravado no passo 3.3).

```go
type Scheduler struct {
    db      *storage.DB
    sec     secrets.Secrets
    notify  *notify.Service
    alerts  *alerts.Service
    version string
}

func NewScheduler(db *storage.DB, sec secrets.Secrets, notify *notify.Service, alerts *alerts.Service, version string) *Scheduler
func (s *Scheduler) Run(ctx context.Context)     // loop do ticker, chamado a partir de main
func (s *Scheduler) RunOnce(ctx context.Context) error // monta+cifra+envia uma vez; usado pelo ticker E pelo botão manual "Enviar agora" (§3.4)
```

`RunOnce`:
1. Monta o `BackupData` (reaproveita `BackupHandler.snapshot()` — exportado ou movido pra um pacote
   compartilhado, ver §5).
2. Cifra com `backup_passphrase` (se não configurado, retorna erro — não deveria acontecer já que
   `PUT /api/backup/schedule` bloqueia isso, mas o agendador confere de novo por defesa em
   profundidade, já que a senha pode ter sido apagada depois de o agendamento já estar ligado).
3. Envia por e-mail como anexo (§3.3) usando a config SMTP já salva em Notificações
   (`notify.Service.LoadConfig().Email`).
4. Grava o resultado (sucesso/falha + timestamp) num novo setting `backup_last_run`
   (`{"at": "...", "ok": true, "error": ""}` serializado em JSON, mesmo padrão do `last_apply` que
   DHCP já usa) — UI mostra isso na tela.
5. Compara com o `backup_last_run` anterior antes de decidir se mexe em `alerts` — **só a transição
   de estado** dispara alerta, nunca o estado repetido, mesmo padrão de `LinkOffline`/`LinkOnline` em
   `internal/failover/service.go` (chamados só dentro do `switch newStatus` de uma mudança de status
   detectada, nunca a cada verificação com o link já no mesmo estado de antes):
   - sucesso após falha (ou primeira execução) → `alerts.BackupSucceeded()`
   - falha após sucesso (ou primeira execução) → `alerts.BackupFailed(detail)`
   - sucesso após sucesso, ou falha após falha → só atualiza `backup_last_run`, não toca `alerts`
     (evita tanto notificação de recuperação repetida a cada backup rotineiro quanto um alerta novo
     por dia enquanto o SMTP continuar fora do ar).

### 3.3 Envio de e-mail com anexo

`internal/notify/notify.go` ganha uma função nova (o `sendEmail` atual continua existindo, sem
mudança, pra alertas de texto puro):

```go
func (s *Service) SendEmailAttachment(subject, body string, attachment []byte, filename string) error
```

Monta uma mensagem MIME multipart (`mime/multipart` da stdlib — sem dependência nova) com uma parte de
texto e uma parte `application/octet-stream` em base64 com o `.lgbak` anexado, usando a mesma `EmailCfg`
(host/port/usuário/senha/from/to) já configurada — se e-mail não estiver habilitado em Notificações,
`RunOnce` retorna erro claro ("configure o e-mail em Notificações primeiro") em vez de tentar mandar.

### 3.4 Botão "Enviar por e-mail agora"

Endpoint novo `POST /api/backup/send-now`, chama `Scheduler.RunOnce` diretamente (fora do ciclo do
ticker) — reaproveita 100% da mesma lógica de montar/cifrar/enviar/alertar/gravar `backup_last_run`.
Isso cobre a ideia original de "endpoint pra executar o backup" sem precisar de autenticação externa
nova: quem quiser automatizar por fora (cron do sistema, por exemplo) pode chamar este endpoint com o
JWT de sessão, do mesmo jeito que qualquer outra chamada autenticada da API hoje.

### 3.5 Alerta de falha

Novo tipo em `internal/alerts/service.go`, mesmo padrão de `DiskFull`/`DiskCleared`:

```go
func (s *Service) BackupFailed(detail string) error {
    return s.Create(TypeBackupFailed, SeverityWarning, "Falha ao enviar backup",
        "O backup automático não pôde ser enviado: "+detail, "")
}
func (s *Service) BackupSucceeded() error {
    s.AutoResolve(TypeBackupFailed, "")
    return s.createRecovery(TypeBackupFailed, "Backup enviado",
        "O backup automático voltou a ser enviado com sucesso.", "")
}
```

Severidade `warning` (não `critical`) — a configuração do servidor não mudou, só a cópia externa que
está atrasada; não é uma queda de serviço.

## 4. Frontend (`web/src/components/BackupRestore.tsx`)

Reskin da rodada 5 não mexeu na lógica deste componente — este spec muda a lógica de verdade pela
primeira vez desde então.

- **Campo de senha** (definir/trocar): dois inputs (senha + confirmação), `PUT /api/backup/passphrase`.
  Mostra "Senha configurada" (via `GET /api/backup/passphrase/status`) ou "Nenhuma senha configurada"
  como hoje mostra "Token configurado" em `UpdateChecker.tsx`.
- **"Baixar backup"**: sem mudança visual, mas fica desabilitado com dica ("configure uma senha
  primeiro") se `!configured`. Nome do arquivo baixado passa a ser `linkguard-backup.lgbak`.
- **"Enviar por e-mail agora"**: botão novo ao lado do "Baixar backup", chama
  `POST /api/backup/send-now`, mesmo tratamento de loading/mensagem que os outros botões da tela.
- **Restaurar de arquivo**: o fluxo de upload ganha um campo de senha que aparece junto da confirmação
  ("Confirmar restauração?") — hoje o arquivo é lido e parseado como JSON no navegador
  (`FileReader`+`JSON.parse`) só pra checar `kind === 'linkguard-fw-backup'`; isso deixa de ser
  possível no browser (o arquivo agora é binário cifrado) — a checagem de "é um backup do LinkGuard
  mesmo?" passa a acontecer no backend, depois de decifrar; o front só precisa validar a extensão
  `.lgbak` antes de aceitar o arquivo e mostrar a mensagem de erro que o backend devolver se a senha
  estiver errada.
- **Agendamento**: seletor "Backup automático: Desligado/Diário/Semanal/Mensal" (mesmo componente
  visual do seletor de retenção de tráfego em `Settings.tsx`), `GET`/`PUT /api/backup/schedule`.
  Desabilitado (com dica) se não houver senha configurada.
- **Status do último envio**: linha "Último backup automático: ok, 29/07 08:00" ou "falhou, 28/07
  08:00 — <detalhe>", lida de `backup_last_run` (endpoint `GET /api/backup/last-run`, reaproveitando o
  mesmo JSON gravado em §3.2 passo 4).

## 5. Arquivos afetados

- **Novo** `internal/backupcrypt/backupcrypt.go` — `Encrypt(plaintext []byte, passphrase string) ([]byte, error)`
  e `Decrypt(ciphertext []byte, passphrase string) ([]byte, error)`, isolado e testável sem tocar HTTP
  nem banco.
- **Novo** `internal/backup/scheduler.go` — `Scheduler` (§3.2).
- **Modificado** `internal/api/handlers/backup.go` — `Export` cifra; `Restore` muda contrato pra
  multipart+senha; novos handlers `PassphraseSet`/`PassphraseStatus`/`ScheduleGet`/`ScheduleSet`/
  `SendNow`/`LastRun`. `snapshot()` fica exportado (`Snapshot`) ou movido pra um pacote comum, já que
  tanto o handler HTTP quanto o `Scheduler` precisam montar o mesmo `BackupData`.
- **Modificado** `internal/notify/notify.go` — `SendEmailAttachment`.
- **Modificado** `internal/alerts/service.go` — `TypeBackupFailed`, `BackupFailed`, `BackupSucceeded`.
- **Modificado** `internal/api/server.go` — registra os novos endpoints e instancia+inicia o
  `Scheduler` (mesmo lugar onde `monitoring.Collector` já é iniciado).
- **Modificado** `web/src/components/BackupRestore.tsx` — UI descrita em §4.
- **Modificado** `web/src/types/index.ts` — tipos novos de resposta (`BackupScheduleResponse`,
  `BackupLastRunResponse`, `BackupPassphraseStatusResponse`).

## 6. Testes

- `internal/backupcrypt`: round-trip cifra/decifra; senha errada falha; ciphertext adulterado (1 byte
  flipado) falha (mesmo padrão de `CorruptCiphertextForTest` que `internal/secrets` já usa); magic
  bytes desconhecido rejeitado com erro claro.
- `internal/api/handlers/backup_test.go`: `Export` devolve bytes cifrados decifráveis com a senha
  configurada; `Export` sem senha configurada devolve erro; `Restore` com senha certa aplica (teste
  existente `TestRestoreReportsMissingSecretsToReconfigure` adaptado pro novo contrato multipart);
  `Restore` com senha errada devolve `400` sem aplicar nada.
- `internal/backup`: `RunOnce` com SMTP configurado e mock/fake de envio confirma o e-mail foi
  "enviado" (interceptando a função de envio, mesmo padrão de `recExec` usado em outros testes do
  projeto) e `backup_last_run` foi gravado; `RunOnce` sem e-mail configurado retorna erro claro sem
  chamar `alerts.BackupFailed` duas vezes por engano.
- `internal/notify`: `SendEmailAttachment` monta um multipart válido (parseável de volta com
  `mime/multipart.Reader`) com o anexo correto em base64.
- Frontend: sem framework de teste (decisão já estabelecida no projeto) — verificação por
  `npm run build` + validação manual do fluxo completo (definir senha → baixar → restaurar em outra
  instância de teste → ligar agendamento → "enviar agora" → checar e-mail chegou → checar alerta
  dispara se SMTP for desligado de propósito).
