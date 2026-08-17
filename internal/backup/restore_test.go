package backup_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/backup"
	"github.com/giovanibalarini/linkguard-fw/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// encryptForTest produz o mesmo formato de arquivo que EncryptSnapshot grava,
// mas a partir de um BackupData montado à mão — os testes da trava precisam de
// um .lgbak cuja senha eles conhecem, sem depender de um banco populado.
func encryptForTest(t *testing.T, data backup.BackupData, passphrase string) []byte {
	t.Helper()
	plaintext, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal BackupData: %v", err)
	}
	ciphertext, err := backupcrypt.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ciphertext
}

func newRestoreDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// validNetsvcConfigJSON é um netsvc_config limpo e inteiramente válido — a
// linha de base que todo teste de "restauração recusada não grava nada"
// restaura antes, para haver estado bom conhecido a provar intacto.
const validNetsvcConfigJSON = `{"backend":"kea-unbound","interface":"br10","subnet_cidr":"192.168.3.0/24","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3","lease_hours":12,"dns_to_clients":["192.168.3.3"],"upstreams":[],"log_queries":false,"domain_suffix":"lan"}`

func backupWith(settings map[string]string) backup.BackupData {
	return backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup", Settings: settings}
}

// ─── Críticos 2 e 3: estado local da máquina não viaja no backup ────────────
//
// Esta guarda mora no domínio (internal/backup) e é provada aqui, e não só
// através de um httptest do handler: um backup de OUTRA máquina não pode
// redefinir esta. nft_live_snapshot é lido no bootstrap
// (cmd/linkguard-fw/main.go) e entregue a `nft -f` como root, com um "flush
// ruleset" na frente — restaurá-lo significaria deixar um arquivo controlar o
// firewall inteiro da máquina de destino, inclusive numa instalação nova (o
// cenário documentado de restauração). firewall_rules_imported é a trava da
// importação única: gravada no destino sem trazer regra nenhuma (BackupData
// não tem campo para regras de firewall), faz o próximo boot pular o
// ImportOnce e o Reconcile esvaziar a chain user_rules viva contra um banco
// vazio. firewall_rules_apply e netsvc_last_apply são resultados de um apply
// que aconteceu na máquina de origem. Nenhuma das quatro é configuração: são
// estado daquela máquina.
func TestApplySkipsMachineLocalStateKeys(t *testing.T) {
	db := newRestoreDB(t)

	data := backupWith(map[string]string{
		"netsvc_config":           validNetsvcConfigJSON,
		"nft_live_snapshot":       "flush ruleset\ntable inet evil { chain c { type filter hook input priority 0; policy accept; } }\n",
		"firewall_rules_imported": "true",
		"firewall_rules_apply":    `{"ok":true,"at":1}`,
		"netsvc_last_apply":       `{"ok":true,"at":1}`,
	})

	res, err := backup.Apply(db, data)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, k := range []string{"nft_live_snapshot", "firewall_rules_imported", "firewall_rules_apply", "netsvc_last_apply"} {
		if v, _ := db.GetSetting(k); v != "" {
			t.Errorf("%q é estado local da máquina e não pode ser restaurado, mas foi gravado: %q", k, v)
		}
	}
	if v, _ := db.GetSetting("netsvc_config"); v != validNetsvcConfigJSON {
		t.Errorf("a configuração de verdade tinha que ser restaurada normalmente, obtive %q", v)
	}
	if res.Settings != 1 {
		t.Errorf("a contagem de settings restauradas não pode incluir as chaves puladas, obtive %d", res.Settings)
	}
	if res.SkippedLocal != 4 {
		t.Errorf("SkippedLocal = %d, esperava 4", res.SkippedLocal)
	}
}

// TestApplyNeverOverwritesAnExistingLiveSnapshot: a guarda vale também quando
// a máquina de destino já tem um ruleset gravado — restaurar não pode trocar
// o firewall desta caixa pelo da caixa de origem.
func TestApplyNeverOverwritesAnExistingLiveSnapshot(t *testing.T) {
	db := newRestoreDB(t)
	const meu = "table inet linkguard { chain input { type filter hook input priority 0; policy drop; } }\n"
	if err := db.SetSetting("nft_live_snapshot", meu); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	if _, err := backup.Apply(db, backupWith(map[string]string{
		"nft_live_snapshot": "flush ruleset\ntable inet outra_maquina { chain c { type filter hook input priority 0; policy accept; } }\n",
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, _ := db.GetSetting("nft_live_snapshot")
	if got != meu {
		t.Fatalf("o ruleset vivo desta máquina foi substituído pelo do backup:\ngot=%q", got)
	}
}

// ─── Validação: nada é gravado quando o arquivo é recusado ──────────────────

func TestApplyRejectsAndWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		data backup.BackupData
	}{
		{"subnet_cidr inválido", backupWith(map[string]string{
			"netsvc_config": `{"backend":"kea-unbound","interface":"br10","subnet_cidr":"not-a-cidr","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3"}`,
		})},
		{"interface inválida", backupWith(map[string]string{
			// Uma quebra de linha em "interface" cairia no interfaces-config do
			// kea-dhcp4.conf por concatenação de string; um nome deste tamanho
			// também é recusado direto por validate.Iface.
			"netsvc_config": `{"backend":"kea-unbound","interface":"this-interface-name-is-way-too-long-for-linux","subnet_cidr":"192.168.3.0/24","range_start":"192.168.3.10","range_end":"192.168.3.100","gateway":"192.168.3.3"}`,
		})},
		{"servidor NTP com injeção", backupWith(map[string]string{
			"ntp_config": `{"servers":["pool.ntp.br\nallow all"],"timezone":"America/Sao_Paulo"}`,
		})},
		{"monitoring com formato errado", backupWith(map[string]string{
			"monitoring": `{"services":{"nao":"e uma lista"}}`,
		})},
		{"domínio de bloqueio com injeção", backup.BackupData{
			Version: "test-version", Kind: "linkguard-fw-backup",
			Blocklist: []string{"good.example.com", "evil.com\ninclude: \"/etc/passwd"},
		}},
		{"reserva DHCP com MAC inválido", backup.BackupData{
			Version: "test-version", Kind: "linkguard-fw-backup",
			Reservations: []storage.DHCPReservation{{MAC: "nao-e-um-mac", IP: "192.168.3.50"}},
		}},
		{"reserva DHCP com IP inválido", backup.BackupData{
			Version: "test-version", Kind: "linkguard-fw-backup",
			Reservations: []storage.DHCPReservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "999.999.1.1"}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newRestoreDB(t)
			// Linha de base boa: é ela que tem de sobreviver intacta.
			if _, err := backup.Apply(db, backup.BackupData{
				Version: "test-version", Kind: "linkguard-fw-backup",
				Settings:     map[string]string{"netsvc_config": validNetsvcConfigJSON},
				Blocklist:    []string{"good.example.com"},
				Reservations: []storage.DHCPReservation{{MAC: "11:22:33:44:55:66", IP: "192.168.3.20"}},
			}); err != nil {
				t.Fatalf("linha de base: %v", err)
			}
			before := snapshotState(t, db)

			_, err := backup.Apply(db, tc.data)
			var invalid *backup.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("esperava *backup.ValidationError, obtive %v", err)
			}

			after := snapshotState(t, db)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("o banco mudou depois de uma restauração que devia ter sido recusada:\nantes=%v\ndepois=%v", before, after)
			}
		})
	}
}

// snapshotState lê as três coleções que uma restauração grava, para provar
// que uma recusa não deixou rastro.
func snapshotState(t *testing.T, db *storage.DB) map[string]any {
	t.Helper()
	settings, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}
	res, err := db.ListDHCPReservations()
	if err != nil {
		t.Fatalf("ListDHCPReservations: %v", err)
	}
	bl, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	return map[string]any{"settings": settings, "reservations": res, "blocklist": bl}
}

// TestApplyCleanBackupRestoresEverything prova que a validação não recusa
// conteúdo legítimo: config, blocklist e reservas entram como vieram (o MAC
// normalizado para minúsculas, como o handler sempre fez).
func TestApplyCleanBackupRestoresEverything(t *testing.T) {
	db := newRestoreDB(t)
	res, err := backup.Apply(db, backup.BackupData{
		Version:      "test-version",
		Kind:         "linkguard-fw-backup",
		Settings:     map[string]string{"netsvc_config": validNetsvcConfigJSON},
		Blocklist:    []string{"ads.example.com", " Tracker.Example.NET "},
		Reservations: []storage.DHCPReservation{{MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.3.50", Hostname: "pc"}},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Settings != 1 || res.Blocklist != 2 || res.Reservations != 1 {
		t.Fatalf("contagens = %+v, esperava 1 setting, 2 domínios, 1 reserva", res)
	}
	if v, _ := db.GetSetting("netsvc_config"); v != validNetsvcConfigJSON {
		t.Errorf("netsvc_config = %q", v)
	}
	bl, _ := db.ListDNSBlocklist()
	if !reflect.DeepEqual(bl, []string{"ads.example.com", "tracker.example.net"}) {
		t.Errorf("blocklist = %v, esperava normalizada para minúsculas e sem espaços", bl)
	}
	rs, _ := db.ListDHCPReservations()
	if len(rs) != 1 || rs[0].MAC != "aa:bb:cc:dd:ee:ff" || rs[0].IP != "192.168.3.50" {
		t.Errorf("reservas = %+v", rs)
	}
}

// TestApplyRestoresUnknownSettingsKeysAsIs: chaves fora do mapa de
// validadores continuam sendo gravadas como vêm — decisão deliberada, não
// esquecimento (ver o doc de Apply).
func TestApplyRestoresUnknownSettingsKeysAsIs(t *testing.T) {
	db := newRestoreDB(t)
	if _, err := backup.Apply(db, backupWith(map[string]string{"balancer_mode": "failover"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if v, _ := db.GetSetting("balancer_mode"); v != "failover" {
		t.Fatalf("balancer_mode = %q, esperava failover", v)
	}
}

// ─── Trava por tentativas ───────────────────────────────────────────────────

func TestRestoreLocksOutAfterRepeatedWrongPassphrase(t *testing.T) {
	db := newRestoreDB(t)
	lim := backup.NewRestoreLimiter()
	ciphertext := encryptForTest(t, backupWith(map[string]string{"balancer_mode": "failover"}), "senha-certa-123456")

	var lastErr error
	for i := 0; i < backup.MaxRestoreAttempts+1; i++ {
		_, lastErr = backup.Restore(db, lim, "u1", ciphertext, "senha-errada-123456")
	}
	if !errors.Is(lastErr, backup.ErrLockedOut) {
		t.Fatalf("esperava ErrLockedOut depois de %d tentativas erradas, obtive %v", backup.MaxRestoreAttempts+1, lastErr)
	}

	// A trava é por usuário: outro usuário não é punido pelas tentativas deste.
	if _, err := backup.Restore(db, lim, "u2", ciphertext, "senha-errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
		t.Fatalf("outro usuário deveria receber ErrBadPassphrase, obtive %v", err)
	}
}

func TestRestoreSuccessResetsAttempts(t *testing.T) {
	db := newRestoreDB(t)
	lim := backup.NewRestoreLimiter()
	const senha = "senha-certa-123456"
	ciphertext := encryptForTest(t, backupWith(map[string]string{"balancer_mode": "failover"}), senha)

	for i := 0; i < backup.MaxRestoreAttempts-1; i++ {
		if _, err := backup.Restore(db, lim, "u1", ciphertext, "errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
			t.Fatalf("tentativa %d: %v", i, err)
		}
	}
	if _, err := backup.Restore(db, lim, "u1", ciphertext, senha); err != nil {
		t.Fatalf("restauração com a senha certa: %v", err)
	}
	// Contador zerado: mais uma errada não pode trancar.
	if _, err := backup.Restore(db, lim, "u1", ciphertext, "errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
		t.Fatalf("esperava ErrBadPassphrase (contador zerado pelo acerto), obtive %v", err)
	}
}
