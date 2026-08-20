package ddns

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

const (
	configKey = "ddns_config"
	stateKey  = "ddns_state"

	// DefaultEndpoint é quem responde "qual é o meu endereço". Configurável,
	// mas com padrão: exigir que o admin escolha um serviço externo antes de
	// usar a feature seria pedir uma decisão que ele não tem como tomar.
	//
	// É uma chamada a um TERCEIRO, e a tela diz isso — só acontece quando o
	// link está atrás de NAT do provedor, porque no caso normal o endereço da
	// própria interface já é o público e ninguém precisa ser consultado.
	DefaultEndpoint = "https://api.ipify.org"
)

// SecretName é onde a senha/token de um link fica guardada.
func SecretName(linkID string) string { return "ddns_" + linkID }

// Service mantém os nomes apontando para os endereços certos.
type Service struct {
	db       *storage.DB
	provider Provider
	updater  *Updater
	// ifaceIP devolve o endereço IPv4 de uma interface. Injetado para o teste
	// não depender da máquina.
	ifaceIP func(ctx context.Context, iface string) string

	mu    sync.Mutex
	nowFn func() time.Time
}

// NewService cria o serviço.
func NewService(db *storage.DB, sec interface{ Get(string) (string, error) },
	ifaceIP func(ctx context.Context, iface string) string) *Service {
	return &Service{
		db:       db,
		provider: NewHTTPProvider(DefaultEndpoint),
		updater: &Updater{SecretFor: func(linkID string) (string, error) {
			return sec.Get(SecretName(linkID))
		}},
		ifaceIP: ifaceIP,
		nowFn:   time.Now,
	}
}

// Configs devolve o que está configurado, por link.
func (s *Service) Configs() (map[string]Config, error) {
	raw, err := s.db.GetSetting(configKey)
	if err != nil || raw == "" {
		return map[string]Config{}, err
	}
	out := map[string]Config{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]Config{}, fmt.Errorf("configuração de DDNS ilegível: %w", err)
	}
	return out, nil
}

// SaveConfig grava a configuração de um link.
func (s *Service) SaveConfig(c Config) error {
	if c.LinkID == "" {
		return fmt.Errorf("link não informado")
	}
	if c.Enabled {
		if c.Hostname == "" {
			return fmt.Errorf("informe o nome que deve apontar para este link")
		}
		// Valida o modelo AGORA, com um endereço qualquer, para o erro
		// aparecer enquanto o admin está na tela — e não daqui a cinco
		// minutos, num log que ele não está lendo.
		if _, err := BuildURL(c.URLTemplate, c.Hostname, netip.MustParseAddr("203.0.113.1")); err != nil {
			return err
		}
	}
	todas, err := s.Configs()
	if err != nil {
		return err
	}
	antiga := todas[c.LinkID]
	todas[c.LinkID] = c
	b, err := json.Marshal(todas)
	if err != nil {
		return err
	}
	if err := s.db.SetSetting(configKey, string(b)); err != nil {
		return err
	}
	// Configuração mexida joga fora o resultado anterior. Sem isto, a
	// verificação seguinte compararia o endereço com o do último sucesso, veria
	// que não mudou e PULARIA — deixando o nome novo (ou a URL corrigida) sem
	// nunca ser publicado até o provedor trocar o IP, o que pode levar semanas.
	// O admin acabou de mexer justamente porque o que estava lá não servia.
	if antiga.Hostname != c.Hostname || antiga.URLTemplate != c.URLTemplate ||
		antiga.Username != c.Username || antiga.Enabled != c.Enabled {
		s.ClearState(c.LinkID)
	}
	return nil
}

// ClearState apaga o resultado da última tentativa de um link, para a próxima
// verificação publicar de novo em vez de decidir que não há nada a fazer.
// Exportado porque o segredo é gravado fora deste pacote: trocar o token também
// precisa forçar a republicação.
func (s *Service) ClearState(linkID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	todos, _ := s.States()
	if _, ok := todos[linkID]; !ok {
		return
	}
	delete(todos, linkID)
	if b, err := json.Marshal(todos); err == nil {
		_ = s.db.SetSetting(stateKey, string(b))
	}
}

// States devolve o resultado da última tentativa por link.
func (s *Service) States() (map[string]State, error) {
	raw, err := s.db.GetSetting(stateKey)
	if err != nil || raw == "" {
		return map[string]State{}, err
	}
	out := map[string]State{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]State{}, nil
	}
	return out, nil
}

func (s *Service) saveState(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	todos, _ := s.States()
	todos[st.LinkID] = st
	if b, err := json.Marshal(todos); err == nil {
		_ = s.db.SetSetting(stateKey, string(b))
	}
}

// Run confere os endereços periodicamente.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(checkInterval)
	defer t.Stop()
	// Uma passada logo na subida: depois de um reboot o endereço pode ter
	// mudado justamente enquanto a máquina estava fora, que é quando o nome
	// mais precisa ser corrigido.
	s.CheckOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.CheckOnce(ctx)
		}
	}
}

// CheckOnce confere todos os links configurados. Exportado para o teste e para
// o botão "verificar agora" da tela.
func (s *Service) CheckOnce(ctx context.Context) {
	cfgs, err := s.Configs()
	if err != nil {
		slog.Warn("ddns: não consegui ler a configuração", "err", err)
		return
	}
	links, err := s.db.GetLinks()
	if err != nil {
		slog.Warn("ddns: não consegui ler os links", "err", err)
		return
	}
	porID := map[string]storage.Link{}
	for _, l := range links {
		porID[l.ID] = l
	}
	estados, _ := s.States()

	for id, c := range cfgs {
		if !c.Enabled {
			continue
		}
		l, ok := porID[id]
		if !ok || l.Interface == "" {
			continue
		}
		st := State{LinkID: id}
		ip, atras, err := s.enderecoPublico(ctx, l.Interface)
		st.BehindNAT = atras
		if err != nil {
			st.LastError = err.Error()
			st.UpdatedAt = s.nowFn().Unix()
			// Preserva o último endereço conhecido: apagá-lo faria a tela dizer
			// "sem endereço" numa falha momentânea de rede, quando o nome
			// continua apontando para um endereço perfeitamente válido.
			if ant, ok := estados[id]; ok {
				st.PublicIP = ant.PublicIP
			}
			s.saveState(st)
			continue
		}
		st.PublicIP = ip.String()

		if ant, ok := estados[id]; ok && ant.PublicIP == st.PublicIP && ant.LastError == "" {
			// Nada mudou e a última tentativa deu certo: não incomodar o
			// provedor. Vários deles tratam atualização repetida do mesmo
			// endereço como abuso e bloqueiam a conta.
			continue
		}
		if err := s.updater.Update(ctx, c, l.IPAddress, ip); err != nil {
			st.LastError = err.Error()
			slog.Warn("ddns: falha ao atualizar", "link", l.Name, "err", err)
		} else {
			slog.Info("ddns: nome atualizado", "link", l.Name, "hostname", c.Hostname, "ip", st.PublicIP)
		}
		st.UpdatedAt = s.nowFn().Unix()
		s.saveState(st)
	}
}

// enderecoPublico devolve o endereço público do link e se ele está atrás de
// NAT do provedor.
//
// O endereço da interface vem primeiro: quando ele já é público, não há por que
// consultar um terceiro — é mais rápido, não vaza que esta máquina existe, e
// não depende de o serviço externo estar de pé.
func (s *Service) enderecoPublico(ctx context.Context, iface string) (netip.Addr, bool, error) {
	bruto := ""
	if s.ifaceIP != nil {
		bruto = s.ifaceIP(ctx, iface)
	}
	if addr, err := netip.ParseAddr(bruto); err == nil && !IsPrivate(addr) {
		return addr, false, nil
	}
	// Endereço da interface é privado ou de CGNAT: o público, se existir, só
	// se descobre perguntando de fora.
	addr, err := s.provider.PublicIP(ctx, bruto)
	if err != nil {
		return netip.Addr{}, true, fmt.Errorf("não consegui descobrir o endereço público: %w", err)
	}
	return addr, true, nil
}
