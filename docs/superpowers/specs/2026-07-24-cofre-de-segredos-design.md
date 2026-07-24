# Cofre de segredos

**Data:** 2026-07-24
**Status:** desenho aprovado, pronto para plano de implementação
**Projeto 3 de 5** — ver `2026-07-23-observabilidade-decisao-e-ia-roadmap.md`

---

## 1. Problema

`GET /api/backup` chamava `ExportSettings()`, que era um `SELECT key, value FROM
settings` sem filtro, servido como arquivo para download. Isso vazava em texto
puro: PAT do GitHub, credenciais de notificação (senha SMTP, tokens Telegram/
WhatsApp) e o **segredo TOTP de cada usuário**.

Um fix emergencial (`188c486`, 2026-07-24) já parou o sangramento — filtra as
chaves conhecidas antes do export. Mas é uma lista de exclusão: **a próxima
feature que criar um segredo pode esquecer de adicioná-lo à lista**, e o vazamento
volta. Este projeto substitui a lista por uma garantia estrutural.

## 2. Princípio norteador

Segredo não mora onde configuração mora. Não é sobre criptografia sofisticada —
é sobre **tornar o vazamento impossível por construção**, em vez de depender de
disciplina.

> Um cofre que ainda deixa a chave ao lado do cadeado não é cofre — é etiqueta.
> A separação de tabela é o que importa; a cifra é a segunda camada, para quando
> o arquivo `.db` sai da máquina sozinho (backup, cópia, disco descartado).

## 3. Escopo

### Dentro
- Tabela `secrets`, separada de `settings`, cifrada em repouso (AES-256-GCM)
- Interface `Secrets` com `Set`/`Get`/`Status`/`Delete`
- Migração automática, no boot, dos 3 segredos existentes
- `ExportSettings()` reduzida à sua forma original (sem lista de exclusão — a
  separação de tabela já garante que segredo não aparece)
- Tela de backup avisando o que precisa ser reinformado após restaurar

### Fora, explicitamente
| Item | Por quê |
|---|---|
| HSM / KMS externo | Fora de propósito para "binário único, drop-in" (I1) |
| Rotação automática de chave | Não há requisito hoje; rotação manual documentada basta |
| Proteção contra root local | Ver §7 — limite reconhecido, não resolvido aqui |
| Múltiplos cofres / por-usuário | YAGNI — um cofre por instalação, como o resto do produto |

## 4. Decisões e suas razões

| Decisão | Razão |
|---|---|
| Tabela **separada**, não coluna extra em `settings` | É a garantia estrutural. `ExportSettings()` nunca alcança `secrets`, mesmo que ninguém lembre de filtrar. Um vazamento futuro exigiria escrever a query errada, não só esquecer uma linha numa lista. |
| **AES-256-GCM** | Autenticado (detecta adulteração), padrão da biblioteca `crypto/aes` do Go, sem dependência nova. |
| Chave de 32 bytes em **arquivo separado**, `/etc/linkguard-fw/secret.key`, `0600` | O vetor real aqui é o `.db` sair da máquina sozinho — backup compartilhado, cópia, disco descartado. Chave em arquivo distinto derrota exatamente esse vetor. |
| Chave **gerada no primeiro boot**, nunca derivada de outro segredo | Não derivar do `jwt_secret`: trocar o JWT secret é operação de segurança normal (ex.: suspeita de vazamento de sessão) e não pode destruir todos os outros segredos como efeito colateral. Ciclos de vida independentes. |
| Migração **automática e idempotente**, no boot | Mesma filosofia do `EnsureForwarding()` / `EnsureAccounting()` já usada no produto — o app é dono do pré-requisito, o admin não faz nada. |

## 5. Arquitetura

```
internal/secrets/           interface Secrets, implementação AES-256-GCM
internal/secrets/keyfile.go geração/leitura da chave em /etc/linkguard-fw/secret.key
```

### 5.1 Interface

```go
type Secrets interface {
    Set(name, plaintext string) error
    Get(name string) (string, error)          // "" se não configurado
    Status(name string) (configured bool, hint string)
    Delete(name string) error
}
```

`hint` é os últimos 4 caracteres do valor, prefixados (`"sk-ant-…7f2a"`), para a
UI confirmar "isso está configurado" sem nunca devolver o segredo inteiro.
Nenhum outro método expõe o texto plano fora de `Get`, que só é chamado no
ponto de uso (ex.: montar o header da chamada à API do Claude), nunca por um
handler HTTP.

### 5.2 Modelo

```sql
CREATE TABLE secrets (
  name       TEXT PRIMARY KEY,   -- "github_update_token" | "notifications" | "totp_<userID>" | "ai_api_token"
  nonce      BLOB NOT NULL,      -- 12 bytes, único por valor
  ciphertext BLOB NOT NULL,      -- AES-256-GCM(plaintext) com tag de autenticação
  updated_at DATETIME NOT NULL
);
```

`name` reaproveita as mesmas chaves que hoje vivem em `settings` — a migração é
uma cópia de linha, não um redesenho de esquema.

### 5.3 Gerenciamento de chave

```
/etc/linkguard-fw/secret.key   0600, 32 bytes aleatórios (crypto/rand)
```

No boot: se o arquivo não existe, gera e grava; se existe, lê. Falha em abrir ou
ler o arquivo é **fatal** — o serviço não sobe com segredos ilegíveis (evita o
pior caso: rodar sem conseguir decifrar e silenciosamente tratar tudo como "não
configurado").

`ReadWritePaths=/etc/linkguard-fw` já existe na unit systemd — nenhuma mudança
de hardening necessária.

### 5.4 Migração

No `DB.migrate()`, após criar a tabela `secrets`:

```go
func migrateSecretsFromSettings(db *sql.DB, sec Secrets) error {
    legacy := []struct{ key, prefix string }{
        {"github_update_token", ""},
        {"notifications", ""},
    }
    for _, l := range legacy {
        moveIfPresent(db, sec, l.key)
    }
    // totp_<userID>: prefixo dinâmico, uma linha por usuário
    rows, _ := db.Query(`SELECT key FROM settings WHERE key LIKE 'totp_%'`)
    for rows.Next() {
        var k string
        rows.Scan(&k)
        moveIfPresent(db, sec, k)
    }
}
```

`moveIfPresent`: lê de `settings`, se existir grava cifrado em `secrets` via
`Set`, então `DELETE FROM settings WHERE key = ?`. Idempotente — se já migrado
(chave ausente em `settings`), é no-op. Roda antes de qualquer handler aceitar
requisição.

### 5.5 Pontos de chamada a atualizar

| Consumidor atual | Troca |
|---|---|
| `internal/updater` (`githubTokenKey`) | `db.GetSetting` / `db.SetSetting` → `secretsSvc.Get` / `.Set` |
| `internal/notify` (`settingKey = "notifications"`) | idem |
| `internal/auth/twofa.go` (`twoFAKey`) | idem |
| `internal/api/handlers/backup.go` | remover a lista de exclusão do fix emergencial — `ExportSettings()` volta a ser `SELECT * FROM settings` sem filtro, porque `secrets` é outra tabela |

## 6. Backup e restauração

`GET /api/backup` continua exportando `settings` (agora limpa por construção,
não por filtro). **Segredos nunca entram no arquivo.**

`POST /api/backup/restore`: após aplicar o backup, a resposta `restoreResult`
ganha um campo `secretsToReconfigure: []string` — a lista de segredos que a
instalação de origem tinha configurados (visível no backup só como `Status`, não
como valor) e que o admin precisa reinformar na tela de destino. Ex.: restaurar
um backup que tinha notificações WhatsApp configuradas mostra "reconfigure a
credencial do WhatsApp" em vez de silenciosamente deixar as notificações mudas.

## 7. Limite honesto

> ⚠️ **Isto não protege contra root na máquina.** O serviço roda como root e lê
> tanto `secret.key` quanto o `.db` — quem tem root lê os dois. O cofre protege
> contra os vetores reais desta instalação: backup compartilhado, `.db` copiado,
> disco descartado, arquivo de backup vazado por engano. Não é HSM, não segura
> contra comprometimento total da máquina, e a documentação do produto não deve
> descrever como tal.

## 8. Testes

| Propriedade | Por que é a que importa |
|---|---|
| `ExportSettings()` nunca contém uma chave presente em `secrets` | é a garantia central — testar que a separação de tabela funciona, não só o filtro antigo |
| `Get` depois de `Set` devolve o mesmo texto plano | round-trip da cifra |
| `nonce` é único por `Set`, mesmo para o mesmo `name` reescrito | reuso de nonce em GCM quebra a autenticação |
| adulterar `ciphertext` faz `Get` falhar, não devolver lixo | GCM autenticado — decifrar dado adulterado deve errar, não vazar texto corrompido silenciosamente |
| migração move os 3 segredos e remove de `settings` | idempotência do boot |
| migração rodada duas vezes é no-op na segunda | idempotência |
| serviço não sobe se `secret.key` existir mas for ilegível (permissão errada) | falhar visível é melhor que rodar cego |

## 9. Riscos

| Risco | Mitigação |
|---|---|
| Perder `secret.key` torna os segredos irrecuperáveis | Documentar explicitamente: perda da chave = reconfigurar tudo manualmente (github token, notificações, todos os 2FA). Não é backup do produto, é chave de máquina — sai do escopo de "backup de config". |
| Migração falha a meio caminho (2 de 3 segredos movidos) | `moveIfPresent` por chave é atômico por linha; uma falha não corrompe as outras. Reboot reexecuta a migração e completa o que faltou. |
| Esquecer um ponto de chamada na migração de consumidores (§5.5) | Grep por `GetSetting\|SetSetting` com os 3 nomes de chave antes de fechar o PR — não deveria sobrar nenhuma referência às chaves antigas fora do módulo de migração. |
