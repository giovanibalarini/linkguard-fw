// Package sysprep is the single place that knows what has to exist on the
// filesystem BEFORE linkguard-fw.service is allowed to start.
//
// Why this is a package and not three copies of the same shell:
//
// The unit runs with ProtectSystem=strict and lists the paths it may write
// to in ReadWritePaths=. systemd builds the mount namespace when the service
// STARTS, and an unprefixed ReadWritePaths= entry that does not exist at
// that moment does not merely get skipped — namespace setup fails and the
// unit dies with 226/NAMESPACE, in a restart loop, without executing a
// single line of the binary (and firing OnFailure=linkguard-notify-down on
// every attempt). Prefixing the entry with `-` avoids the crash but does NOT
// create a mount: a directory that appears later (because apt installed the
// package that owns it) stays read-only for the already-running process.
//
// Until now this pre-creation lived only in the .deb's postinst, so
// `deploy/install.sh` and `make install` produced a machine where the
// service could not start at all — reproduced on the bare test VM:
//
//	linkguard-fw.service: Failed to set up mount namespacing:
//	/etc/nftables.conf: No such file or directory
//	linkguard-fw.service: Main process exited, code=exited, status=226/NAMESPACE
//
// All three installation paths now call the same code: the binary itself,
// via `linkguard-fw --prepare-system`. The .deb can do that because postinst
// runs after the binary is unpacked; install.sh and `make install` do it
// right after copying the binary into place.
//
// Existe um QUARTO chamador, e ele não é um instalador: a própria unidade,
// em `ExecStartPre=-+/usr/local/bin/linkguard-fw --prepare-system-at-start`.
// Ele existe porque um dos caminhos — /etc/nftables.conf — é conffile do
// pacote `nftables` e não pode ser criado de dentro de uma transação do
// dpkg. Ver o tipo Stage.
//
// TestEveryUnprefixedReadWritePathIsPrepared and its siblings
// (packaging_test.go) tie this list to the unit file and to the three
// installers, so the next path added to ReadWritePaths= cannot silently
// reopen the trap.
package sysprep

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// NftablesConfPath is the ruleset file LinkGuard owns end to end. It used to
// arrive with the nftables package (a Depends:); since the base moved to
// Recommends: — so `dpkg -i` on a bare box installs AND configures, and the
// service comes up to install the base itself — it may simply not exist on a
// first boot.
const NftablesConfPath = "/etc/nftables.conf"

// Stage says WHO is calling Prepare, because the answer changes what may be
// created.
//
// O motivo é um defeito reproduzido em VM pelada: `/etc/nftables.conf` é
// conffile do pacote `nftables`. Se o instalador do LinkGuard o cria e o
// dpkg desempacota o `nftables` DEPOIS (o que é livre para acontecer, porque
// a base fica em Recommends: e não em Depends:), o dpkg encontra um conffile
// que ele não escreveu e para para perguntar a quem obedecer:
//
//	Configuration file '/etc/nftables.conf'
//	 ==> File on system created by you or by a script.
//	*** nftables.conf (Y/I/N/O/D/Z) [default=N] ? dpkg: error processing
//	    package nftables (--configure): end of file on stdin at conffile prompt
//
// Interativo o apt trava esperando; não interativo ele morre e o `nftables`
// fica em `iU`. `DEBIAN_FRONTEND=noninteractive` não cobre isso — prompt de
// conffile é do dpkg, não do debconf.
//
// A saída não é criar o arquivo mais cedo nem mais tarde no postinst: é
// criá-lo FORA da transação do dpkg, na partida do serviço (ExecStartPre=-+
// na unidade). Nesse instante o apt já terminou, e o pacote `nftables` — se
// veio junto — já registrou o conffile dele. Ver o comentário de
// OnlyAtServiceStart para a semântica do systemd que foi medida antes de
// escolher isto.
type Stage int

const (
	// StageInstall é o postinst do .deb, o deploy/install.sh e o
	// `make install`: rodam com o dpkg no comando (ou logo antes dele).
	StageInstall Stage = iota
	// StageServiceStart é o ExecStartPre da unidade, fora de qualquer
	// transação do dpkg.
	StageServiceStart
)

// nftablesConfSeed is what an empty, LinkGuard-owned ruleset file looks like.
// Creating it empty is safe: the first Persist() rewrites the whole file, and
// this header is exactly what Persist() generates on top.
const nftablesConfSeed = "#!/usr/sbin/nft -f\n\n" +
	"# Arquivo gerenciado pelo LinkGuard FW.\n" +
	"# Vazio até o primeiro apply de firewall.\n"

// Entry is one filesystem object the service needs in place before it starts.
type Entry struct {
	// Path is absolute, exactly as it appears in the unit's ReadWritePaths=.
	Path string
	// Dir distinguishes a directory (created with MkdirAll) from a seeded file.
	Dir bool
	// Mode is applied only when this run creates the object. An entry that
	// already exists is left alone: on a box that already has the owning
	// package, the owner/mode belong to that package.
	Mode fs.FileMode
	// Seed is the initial content of a file entry.
	Seed string
	// Why is the one-line reason, printed by --prepare-system so an operator
	// reading the install log can tell what this is for.
	Why string
	// OnlyAtServiceStart marks an object que os instaladores NÃO podem criar
	// (ver Stage): ele só nasce no ExecStartPre da unidade.
	//
	// Isto só é seguro por causa de duas coisas medidas no systemd 257
	// (Debian 13), não presumidas — o roteiro está em
	// TestPreparoDeStartExigeCaminhoOpcionalEExecStartPrePrivilegiado:
	//
	//  1. O namespace de montagem é montado UMA VEZ POR COMANDO, não uma vez
	//     por unidade. Um ExecStartPre que cria o caminho é enxergado pelo
	//     ExecStart, que monta o namespace dele depois — com o caminho já
	//     existindo, ele entra como gravável.
	//  2. O prefixo `+` tira o comando do ProtectSystem=strict (sem ele,
	//     escrever em /etc devolve "Read-only file system"), mas NÃO o tira
	//     da montagem do namespace: com a entrada sem `-` em
	//     ReadWritePaths=, o próprio ExecStartPre=+ morre em 226/NAMESPACE
	//     antes de criar coisa alguma. Por isso toda entrada marcada aqui
	//     PRECISA aparecer na unidade com o prefixo `-`.
	OnlyAtServiceStart bool
}

// Entries is the whole contract, in the order they are created.
var Entries = []Entry{
	{
		Path: "/var/lib/linkguard-fw", Dir: true, Mode: 0o750,
		Why: "estado do LinkGuard (banco, marcadores de aplicação)",
	},
	{
		Path: "/etc/linkguard-fw", Dir: true, Mode: 0o750,
		Why: "configuração do LinkGuard",
	},
	{
		// O ponto de extensão do AppArmor do unbound (issue #116).
		//
		// O diretório vem do pacote `apparmor`, mas ele é OPCIONAL na unidade
		// (`-` em ReadWritePaths=), e entrada opcional que não existe no start
		// simplesmente não é montada — a primeira escrita falharia com
		// "Read-only file system" e só voltaria a funcionar depois de um
		// restart do serviço. Numa caixa sem AppArmor instalado, criar o
		// diretório é inofensivo; o que ele guarda só tem efeito se houver
		// AppArmor para ler.
		//
		// OnlyAtServiceStart pela mesma razão do /etc/nftables.conf: o caminho
		// pertence a outro pacote, e criá-lo no postinst arrisca prompt de
		// conffile do dpkg numa instalação pelada.
		Path: "/etc/apparmor.d/local", Dir: true, Mode: 0o755,
		Why:                "regra que autoriza o unbound a entregar dnstap; sem o diretório montado a escrita falha em read-only até o próximo restart",
		OnlyAtServiceStart: true,
	},
	{
		// OnlyAtServiceStart: este é o único caminho da lista que pertence a
		// OUTRO pacote (é conffile do `nftables`). Criá-lo no postinst fazia
		// `apt install ./linkguard-fw_*.deb` numa máquina pelada parar no
		// prompt de conffile do dpkg — ver Stage.
		Path: NftablesConfPath, Dir: false, Mode: 0o644, Seed: nftablesConfSeed,
		Why:                "regras do firewall; sem ele a unidade morre em 226/NAMESPACE e nunca chega a instalar o nftables",
		OnlyAtServiceStart: true,
	},
	{
		Path: "/etc/kea", Dir: true, Mode: 0o755,
		Why: "config do DHCP; precisa existir no start para o kea instalado sob demanda ser configurável sem reiniciar",
	},
	{
		Path: "/etc/unbound/unbound.conf.d", Dir: true, Mode: 0o755,
		Why: "config do DNS; mesma razão do /etc/kea",
	},
	{
		// Mesma armadilha do /etc/kea, reproduzida na VM com o serviço no ar
		// desde antes do chrony existir na máquina:
		//
		//   # nsenter -t $(pidof linkguard-fw) -m -- \
		//       sh -c 'echo > /etc/chrony/conf.d/linkguard.conf'
		//   sh: cannot create ...: Read-only file system
		//
		// O erro chegava ao last_apply da tela de NTP sem nem a dica de
		// reiniciar o serviço (SandboxHint) que o caminho do DHCP/DNS tem.
		Path: "/etc/chrony/conf.d", Dir: true, Mode: 0o755,
		Why: "drop-in do NTP; o chrony é instalado sob demanda e o diretório precisa existir desde o start",
	},
	{
		// Está na unidade SEM o prefixo `-` (é o sysctl drop-in do
		// conntrack accounting) e não era criado por ninguém: vinha de
		// graça do pacote procps. Mesma classe de risco do
		// /etc/nftables.conf — se um dia faltar, a unidade morre em
		// 226/NAMESPACE. O comentário da unidade já afirmava que o postinst
		// o criava; agora é verdade.
		Path: "/etc/sysctl.d", Dir: true, Mode: 0o755,
		Why: "drop-in de sysctl (conntrack accounting); entrada sem `-` na unidade",
	},
}

// Prepare creates whatever is missing, under root (""/"/" for the real
// filesystem; a temp dir in tests). It is idempotent and never touches an
// object that already exists.
//
// stage decide o que pode ser criado: um instalador (StageInstall) roda
// dentro da transação do dpkg e por isso não toca em objeto de outro pacote;
// a partida do serviço (StageServiceStart) roda fora dela e cria tudo.
//
// It returns one human-readable line per object it actually created — the
// install log an operator reads — and the first error that stopped it.
func Prepare(root string, stage Stage) ([]string, error) {
	var created []string
	for _, e := range Entries {
		if e.OnlyAtServiceStart && stage != StageServiceStart {
			continue
		}
		path := filepath.Join(root, e.Path)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if e.Dir {
			if err := os.MkdirAll(path, e.Mode); err != nil {
				return created, fmt.Errorf("criar %s: %w", e.Path, err)
			}
			// MkdirAll honours umask; force the intended mode.
			if err := os.Chmod(path, e.Mode); err != nil {
				return created, fmt.Errorf("ajustar modo de %s: %w", e.Path, err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return created, fmt.Errorf("criar %s: %w", filepath.Dir(e.Path), err)
			}
			if err := os.WriteFile(path, []byte(e.Seed), e.Mode); err != nil {
				return created, fmt.Errorf("criar %s: %w", e.Path, err)
			}
			if err := os.Chmod(path, e.Mode); err != nil {
				return created, fmt.Errorf("ajustar modo de %s: %w", e.Path, err)
			}
		}
		created = append(created, e.Path+" — "+e.Why)
	}
	return created, nil
}

// Paths returns just the paths, for the packaging tests and for anyone who
// needs to know what this package owns.
func Paths() []string {
	out := make([]string, 0, len(Entries))
	for _, e := range Entries {
		out = append(out, e.Path)
	}
	return out
}

// SandboxHint turns "cannot write there" into something the admin can act
// on, and is shared by every feature that writes into /etc: the likely cause
// is specific and non-obvious, and the sentence is identical whether the
// path is /etc/kea (DHCP), /etc/unbound/unbound.conf.d (DNS) or
// /etc/chrony/conf.d (NTP).
//
// LinkGuard runs under ProtectSystem=strict and systemd builds the unit's
// mount namespace when the service STARTS — a directory that did not exist
// at that moment is not in the namespace, so it stays read-only for the
// running process even after apt creates it. Prepare pre-creates all of them
// precisely so a first-ever apply does not hit this; the message exists for
// the installs that bypass it (an old package, a directory removed by hand).
//
// Errors that are not that trap (a full disk, a permission problem) get the
// plain reason: inventing a namespace explanation for them would send the
// admin to restart a service that will fail exactly the same way.
func SandboxHint(path string, err error) string {
	if !isSandboxTrap(err) {
		return fmt.Sprintf("o LinkGuard não consegue escrever em %s (%v)", path, err)
	}
	return fmt.Sprintf("o LinkGuard não consegue escrever em %s (%v). "+
		"Isso costuma acontecer quando o caminho passou a existir depois que o serviço subiu: "+
		"o sandbox do systemd (ProtectSystem=strict) só enxerga como gravável o que já existia no start. "+
		"Reinicie o serviço uma vez — systemctl restart linkguard-fw — e aplique de novo; "+
		"a configuração não vai valer até isso ser resolvido", path, err)
}

// isSandboxTrap recognises the two shapes the trap takes: the path is inside
// a read-only mount (EROFS), or it simply is not there because the namespace
// never picked it up (ENOENT).
func isSandboxTrap(err error) bool {
	return errors.Is(err, syscall.EROFS) || errors.Is(err, fs.ErrNotExist)
}

// Covers reports whether Prepare guarantees the given path exists: it is one
// of the entries, it lives inside a directory this package creates, or it is
// an ancestor of one (MkdirAll creates /etc/unbound on the way to
// /etc/unbound/unbound.conf.d).
func Covers(path string) bool {
	for _, e := range Entries {
		switch {
		case e.Path == path:
			return true
		case e.Dir && strings.HasPrefix(path, e.Path+"/"):
			return true
		case strings.HasPrefix(e.Path, path+"/"):
			return true
		}
	}
	return false
}
