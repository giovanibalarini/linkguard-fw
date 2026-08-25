// Package hostflows responde "com quem esse host falou" (issue #115).
//
// O DADO NÃO MORA NO BANCO, E ISSO É DE PROPÓSITO. A issue pede uma tabela
// "flows" com retenção; o levantamento contra o código mostrou o preço:
// internal/storage abre o SQLite com SetMaxOpenConns(1), e milhões de INSERT
// por dia entrariam na MESMA fila única que a janela de confirmação de 90 s do
// firewall usa. Um banco ocupado atrasa o confirm do operador — e um confirm
// que não completa a tempo dispara o auto-revert sozinho no meio de uma mudança
// boa. É o caminho pelo qual um registro de tráfego tranca o admin fora da
// caixa.
//
// Então o registro é uma JANELA ROLANTE mantida pelo kernel: um set nft com
// timeout, chaveado pela tupla origem-destino-porta (ver
// internal/nftables/flows.go). A retenção é o timeout do set, escolhido em
// minutos. Nada é escrito em disco, nada entra na fila do SQLite, e o dado some
// no reboot — que é o comportamento certo para algo que afirma "na última
// hora".
//
// O QUE ESTA FASE NÃO SABE, e a tela é obrigada a dizer: não tem duração de
// fluxo, não tem por qual WAN o fluxo saiu, não conta ICMP nem IPv6, e a
// medição pode estar CHEIA. Só o evento de destruição do conntrack entrega
// duração e WAN de saída, e esse caminho tem custo próprio.
package hostflows

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/nftables"
)

// ConfigSettingKey é a chave em "settings". Ausente resolve para DESLIGADO,
// que é o estado de toda máquina anterior a esta entrega — e o único estado
// honesto para um registro de quem-falou-com-quem que ninguém pediu.
const ConfigSettingKey = "flows_registro"

// ValidadeDoCache é por quanto tempo uma leitura do set serve outra consulta.
//
// Existe por dois motivos que não são otimização. O primeiro: um "nft list
// set" de milhares de elementos a cada segundo é CPU e latência de painel numa
// appliance de 2 GB — a tela nova fica aberta, e o navegador repolla. O segundo
// é o oposto e é o que manda no valor: o cache NÃO pode sobreviver à janela do
// set, senão a tela continua mostrando números velhos depois de o tráfego
// parar. Dez segundos é curto o bastante para nunca competir com a janela
// mínima (5 min) e longo o bastante para o repolling não virar um nft por
// segundo.
const ValidadeDoCache = 10 * time.Second

// Firewall é o que este pacote precisa do nftables. É interface, e não o
// *nftables.Service direto, para o serviço ser testável de mesa — sem kernel,
// sem root e sem VM.
type Firewall interface {
	EnsureFlows(ctx context.Context, wanInterfaces []string, cfg nftables.FlowsConfig) error
	DisableFlows(ctx context.Context) error
	Flows(ctx context.Context) (nftables.FlowSnapshot, error)
}

// Banco é a fatia de storage.DB usada aqui, pelo mesmo motivo.
type Banco interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
}

// Nomes traduz endereço para nome de domínio. É a mesma forma do
// dnstap.Mapa.Nome (#116), e é opcional: sem coletor de dnstap o destino
// aparece como endereço cru e a tela diz por quê.
type Nomes interface {
	Nome(a netip.Addr) (string, bool)
}

// Servico responde as consultas e reconcilia a estrutura no kernel.
type Servico struct {
	fw    Firewall
	banco Banco
	nomes Nomes

	// agora e validade são campos (e não time.Now e a constante) para o teste
	// do cache poder andar com o relógio sem dormir.
	agora    func() time.Time
	validade time.Duration

	mu       sync.Mutex
	cache    nftables.FlowSnapshot
	cacheEm  time.Time
	temCache bool
}

// NovoServico cria o serviço.
func NovoServico(fw Firewall, banco Banco) *Servico {
	return &Servico{fw: fw, banco: banco, agora: time.Now, validade: ValidadeDoCache}
}

// SetNomes liga o mapa endereço-para-nome. Opcional.
func (s *Servico) SetNomes(n Nomes) { s.nomes = n }

// Config devolve o que o admin escolheu, já dentro dos limites.
//
// Chave ausente é DESLIGADO. Erro de leitura PROPAGA, e a diferença importa: um
// SELECT que falhou não é "o admin não ligou o registro", e resolver o
// silêncio para desligado faria a reconciliação do boot derrubar a tabela de uma
// caixa cuja feature está ligada — apagando a janela inteira por causa de um
// erro de banco. Mesma decisão de firewallrules.EdgeContainment.
func (s *Servico) Config() (nftables.FlowsConfig, error) {
	bruto, err := s.banco.GetSetting(ConfigSettingKey)
	if err != nil {
		return nftables.FlowsConfig{}, fmt.Errorf("ler a configuração do registro de conversa: %w", err)
	}
	cfg := nftables.FlowsConfig{}
	if bruto != "" {
		if err := json.Unmarshal([]byte(bruto), &cfg); err != nil {
			// JSON corrompido não pode virar desligado silencioso nem derrubar
			// a tela: cai no padrão desligado COM erro, para quem chama poder
			// dizer o que houve.
			return nftables.NormalizeFlowsConfig(nftables.FlowsConfig{}),
				fmt.Errorf("configuração do registro de conversa ilegível: %w", err)
		}
	}
	return nftables.NormalizeFlowsConfig(cfg), nil
}

// SalvarConfig grava a escolha do admin e APLICA no kernel.
//
// DERRUBA A TABELA ANTES DE RECRIAR, sempre. O add-set do nft é idempotente e
// IGNORA a spec quando o set já existe: sem o delete, mudar a janela de 60 para
// 15 minutos gravaria 15 no banco e deixaria o kernel com 60. A tela mostraria a
// janela nova sobre um dado que obedece à velha — exatamente a classe de mentira
// que este produto não pode ter.
//
// O custo é honesto e precisa estar na tela: mudar a configuração ZERA a
// janela. Não existe trocar o timeout de um set mantendo as tuplas.
func (s *Servico) SalvarConfig(ctx context.Context, cfg nftables.FlowsConfig, wans []string) error {
	cfg = nftables.NormalizeFlowsConfig(cfg)
	bruto, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serializar a configuração do registro de conversa: %w", err)
	}
	if err := s.banco.SetSetting(ConfigSettingKey, string(bruto)); err != nil {
		return fmt.Errorf("gravar a configuração do registro de conversa: %w", err)
	}
	s.invalidarCache()

	if err := s.fw.DisableFlows(ctx); err != nil {
		return err
	}
	if !cfg.Ligado {
		return nil
	}
	return s.fw.EnsureFlows(ctx, wans, cfg)
}

// Reconciliar põe o kernel de acordo com a configuração — no boot e a cada
// mudança de link, pelo mesmo motivo de EnsureAccounting: EnsureTable é no-op
// em máquina já provisionada.
//
// NÃO derruba a tabela antes, ao contrário de SalvarConfig: aqui a configuração
// não mudou, e derrubar apagaria a janela a cada mudança de link. O que se perde
// é uma alteração de janela feita direto no banco sem passar pela tela — e essa
// não é uma via suportada.
func (s *Servico) Reconciliar(ctx context.Context, wans []string) error {
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if !cfg.Ligado {
		return s.fw.DisableFlows(ctx)
	}
	return s.fw.EnsureFlows(ctx, wans, cfg)
}

// Conversa é uma linha da tela: com quem o host falou, em que porta, e quanto.
type Conversa struct {
	Origem  string `json:"origem"`
	Destino string `json:"destino"`
	// Nome é o domínio que o resolver associou ao destino, quando o mapa da
	// #116 conhece o endereço. Vazio quer dizer "não sei" — e a tela mostra
	// o endereço cru em vez de inventar.
	Nome    string `json:"nome"`
	Porta   uint16 `json:"porta"`
	Pacotes uint64 `json:"pacotes"`
	Bytes   uint64 `json:"bytes"`
}

// Resposta é o que a tela recebe: as linhas MAIS tudo o que ela precisa admitir
// sobre elas.
type Resposta struct {
	Ligado bool   `json:"ligado"`
	Host   string `json:"host"`
	// JanelaMinutos é a janela que o KERNEL está aplicando, não a que está
	// salva no banco. Ver nftables.FlowSnapshot.
	JanelaMinutos int        `json:"janela_minutos"`
	Conversas     []Conversa `json:"conversas"`
	// TotalConversas é quantas linhas CASARAM, antes do corte do limite. Sem
	// ele, uma tela que mostra 50 de 312 destinos parece a lista completa — e o
	// admin conclui que o host não falou com o resto.
	TotalConversas int    `json:"total_conversas"`
	TotalBytes     uint64 `json:"total_bytes"`
	// Cheio é o teto do set batido: há conversa que NÃO coube na medição.
	Cheio bool `json:"cheio"`
	Teto  int  `json:"teto"`
	// NomesLigados diz se o mapa de domínios está disponível. Sem isto, uma
	// coluna de nomes vazia parece "nenhum destino tem nome" quando a
	// verdade é "o produto não está olhando o DNS".
	NomesLigados bool `json:"nomes_ligados"`
}

// LimitePadrao e LimiteMaximo cortam a lista devolvida. O corte é declarado na
// resposta (TotalConversas), nunca escondido.
const (
	LimitePadrao = 50
	LimiteMaximo = 500
)

// Consultar responde com quem o host falou na janela.
//
// host vazio significa TODOS os hosts — a visão de rede. É legítima e é a que
// responde "quem encheu a wan1 às 3h" dentro da janela, mas é também a mais
// cara em linhas, e por isso passa pelo mesmo corte declarado.
func (s *Servico) Consultar(ctx context.Context, host string, limite int) (Resposta, error) {
	cfg, err := s.Config()
	if err != nil {
		return Resposta{}, err
	}
	if !cfg.Ligado {
		// Desligado NÃO é erro e não é lista vazia disfarçada: a tela precisa
		// distinguir "ninguém falou" de "o produto não está olhando".
		return Resposta{Ligado: false, Host: host, Conversas: []Conversa{}}, nil
	}

	snap, err := s.instantaneo(ctx)
	if err != nil {
		return Resposta{}, err
	}

	linhas, total, bytes := agregar(snap.Fluxos, host, limite)
	s.batizar(linhas)
	return Resposta{
		Ligado:         true,
		Host:           host,
		JanelaMinutos:  snap.JanelaMinutos,
		Conversas:      linhas,
		TotalConversas: total,
		TotalBytes:     bytes,
		Cheio:          snap.Cheio,
		Teto:           snap.Teto,
		NomesLigados:   s.nomes != nil,
	}, nil
}

// agregar filtra pelo host, ordena por volume e corta no limite.
//
// PURA de propósito: é a parte que dá para provar de mesa, sem kernel e sem
// root, e é onde moram os dois defeitos que a tela não perdoa — o corte que se
// apresenta como lista completa e a ordem que muda sozinha entre duas leituras.
//
// O total é somado sobre TUDO o que casou, não sobre o que sobrou depois do
// corte: é o que permite a tela dizer "50 de 312" em vez de fingir que 50 é
// tudo.
func agregar(fluxos []nftables.Flow, host string, limite int) ([]Conversa, int, uint64) {
	if limite <= 0 {
		limite = LimitePadrao
	}
	if limite > LimiteMaximo {
		limite = LimiteMaximo
	}

	linhas := make([]Conversa, 0, len(fluxos))
	var totalBytes uint64
	for _, f := range fluxos {
		if host != "" && f.Origem != host {
			continue
		}
		totalBytes += f.Bytes
		linhas = append(linhas, Conversa{
			Origem: f.Origem, Destino: f.Destino, Porta: f.Porta,
			Pacotes: f.Pacotes, Bytes: f.Bytes,
		})
	}

	sort.Slice(linhas, func(i, j int) bool {
		if linhas[i].Bytes != linhas[j].Bytes {
			return linhas[i].Bytes > linhas[j].Bytes
		}
		// Desempate estável, pelo mesmo motivo de hosttraffic.rankHosts: sem
		// ele a ordem entre duas conversas de mesmo volume muda a cada leitura
		// e a tela pisca sozinha na frente do admin.
		if linhas[i].Origem != linhas[j].Origem {
			return linhas[i].Origem < linhas[j].Origem
		}
		if linhas[i].Destino != linhas[j].Destino {
			return linhas[i].Destino < linhas[j].Destino
		}
		return linhas[i].Porta < linhas[j].Porta
	})

	total := len(linhas)
	if total > limite {
		linhas = linhas[:limite]
	}
	return linhas, total, totalBytes
}

// batizar preenche o nome do destino a partir do mapa da #116, só para as
// linhas que a tela vai mostrar.
//
// Endereço que o mapa não conhece fica com Nome vazio, e é a tela que mostra o
// endereço cru. Inventar um nome aqui — o último que aquele endereço teve, por
// exemplo — é precisamente o que o TTL do mapa existe para impedir: endereço de
// CDN é de um site hoje e de outro daqui a dez minutos.
func (s *Servico) batizar(linhas []Conversa) {
	if s.nomes == nil {
		return
	}
	for i := range linhas {
		a, err := netip.ParseAddr(linhas[i].Destino)
		if err != nil {
			continue
		}
		if nome, ok := s.nomes.Nome(a); ok {
			linhas[i].Nome = nome
		}
	}
}

// instantaneo devolve o set, relendo o kernel só quando o cache venceu.
//
// O DEFEITO QUE O VENCIMENTO PRENDE: sem prazo, o painel aberto continuaria
// mostrando as conversas da última leitura depois de o tráfego parar e de o
// kernel ter expirado as tuplas. Um painel que congela o último valor conhecido
// é a definição de mentir na tela — e é justamente o que a janela rolante
// existe para não fazer.
//
// O DEFEITO QUE O CACHE PRENDE, do outro lado: um nft-list-set por segundo, com
// milhares de elementos, numa appliance de 2 GB, toda vez que o navegador
// repolla.
func (s *Servico) instantaneo(ctx context.Context) (nftables.FlowSnapshot, error) {
	s.mu.Lock()
	if s.temCache && s.agora().Sub(s.cacheEm) < s.validade {
		snap := s.cache
		s.mu.Unlock()
		return snap, nil
	}
	s.mu.Unlock()

	// A leitura acontece FORA do lock: ela executa um processo externo, e
	// segurar o mutex durante isso enfileiraria todas as abas do painel atrás
	// de um nft lento. O preço é duas leituras simultâneas na virada do prazo,
	// que é barato e correto — as duas devolvem o mesmo estado do kernel.
	snap, err := s.fw.Flows(ctx)
	if err != nil {
		return nftables.FlowSnapshot{}, err
	}

	s.mu.Lock()
	s.cache, s.cacheEm, s.temCache = snap, s.agora(), true
	s.mu.Unlock()
	return snap, nil
}

// invalidarCache descarta a leitura guardada.
//
// Chamado ao salvar a configuração porque ali a tabela é derrubada e recriada:
// sem isto, a tela mostraria por até ValidadeDoCache as conversas de um set que
// não existe mais, com a janela nova no rótulo.
func (s *Servico) invalidarCache() {
	s.mu.Lock()
	s.cache, s.temCache = nftables.FlowSnapshot{}, false
	s.mu.Unlock()
}
