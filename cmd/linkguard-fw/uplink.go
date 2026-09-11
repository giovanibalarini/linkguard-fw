package main

import (
	"fmt"
	"log/slog"

	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/platform"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

// O UPLINK IMPLÍCITO — por onde esta máquina sai para a Internet quando
// ninguém cadastrou nada.
//
// ─── O PROBLEMA ──────────────────────────────────────────────────────────────
//
// Este é um produto de prateleira: quem instala numa VM de nuvem recém-criada
// tem de receber uma máquina que FUNCIONA, pelo menos liberando tráfego por
// NAT, e configurar o resto pela tela. Até aqui não era isso que acontecia. A
// chain postrouting nascia vazia e nada saía, porque ReconcileMasquerade se
// recusa — corretamente — a agir com a lista de WANs vazia, e a lista vinha da
// tabela `links`, que numa instalação nova não tem linha nenhuma.
//
// ─── O QUE ESTE ARQUIVO NÃO FAZ ──────────────────────────────────────────────
//
// NÃO CADASTRA LINK, e isso é a decisão inteira. Um atalho que criasse a linha
// sozinho cairia direto na armadilha: links.Service.Create SEMPRE atribui
// TableID >= 100, e links.WANPaths devolve caminho para todo link com TableID
// > 0 — a partir daí o produto começa a escrever `ip rule`, tabelas de policy
// routing, marca de conexão por link, rota de retorno, monitor e failover numa
// máquina de UMA VNIC, onde a rota default é do DHCP da fabric e não existe
// segunda tabela a consultar.
//
// Sem linha em `links` nada disso liga, e não liga POR CONSTRUÇÃO — não por
// uma guarda nova que alguém possa esquecer de manter. O uplink implícito
// alimenta a fonte de verdade das WANs e para por aí.
//
// ─── A GUARDA TAMBÉM NÃO SAIU ────────────────────────────────────────────────
//
// A recusa de ReconcileMasquerade com lista vazia continua exatamente onde
// estava. O que mudou não foi a guarda: foi a lista deixar de chegar vazia numa
// máquina em que a plataforma sabe responder.

// Uplink é por onde esta máquina sai para a Internet, e o que o caminho de
// saída suporta.
//
// Valor e não ponteiro, zero-value == "não sei" — a mesma disciplina de
// platform.Snapshot e de nftables.Zone: o caminho que esquecer de preencher se
// comporta como o produto se comporta hoje.
type Uplink struct {
	// Interface é a placa de saída. "" = desconhecido, e desconhecido tem de
	// continuar produzindo lista VAZIA, isto é, a guarda de ReconcileMasquerade
	// intacta.
	Interface string
	// PathMTU é o que o CAMINHO até a Internet suporta, não o que a interface
	// anuncia. 0 = desconhecido. Ver platform.NetFacts.PathMTU: numa VM da OCI
	// a placa anuncia 9000 e o caminho aceita 1500.
	PathMTU int
	// Implicito diz que ninguém cadastrou nada: isto saiu da plataforma. É o
	// que o painel mostra, e o que separa "o admin decidiu" de "o produto
	// deduziu".
	Implicito bool
}

// uplinkDaPlataforma devolve o uplink que a plataforma AFIRMA, ou o zero-value.
//
// A GUARDA É O CORAÇÃO DESTA ENTREGA, e ela é estreita de propósito:
//
//   - Kind.IsCloud() && Confidence == ConfidenceAuthoritative: só quando o IMDS
//     do provedor CONFIRMOU. "Achei que era nuvem por um sinal local" não é
//     autoridade suficiente para começar a mascarar tráfego sozinho;
//   - !Capable().RoutedTransit: uma VNIC só. Com duas, "por onde se sai" tem
//     mais de uma resposta, e quem responde é o admin, cadastrando o link;
//   - Net.PrimaryInterface != "": sem nome de placa não há o que escrever.
//
// FORA DA NUVEM ISTO NUNCA DISPARA, e é a propriedade que protege a caixa de
// produção. Numa Debian on-prem recém-instalada e sem link cadastrado,
// Facts.Net.PrimaryInterface ESTÁ preenchido — é uma eleição: a rota default,
// ou a primeira placa que não é de sistema — e pode perfeitamente apontar para
// a interface da LAN. Derivar o uplink dali poria masquerade na placa de
// DENTRO: NAT para o lado errado numa caixa que hoje, corretamente, não faz NAT
// nenhum. Nuvem + autoritativo + VNIC única é o único conjunto em que a fabric
// é a autoridade sobre qual é o lado de fora.
func uplinkDaPlataforma(plat platform.Snapshot) Uplink {
	if !plat.Facts.Kind.IsCloud() || plat.Facts.Confidence != platform.ConfidenceAuthoritative {
		return Uplink{}
	}
	// Capable() e não o campo Capabilities: instantâneo de formato velho ou
	// incompleto devolve o conjunto PERMISSIVO, isto é, RoutedTransit true,
	// isto é, nada de uplink implícito. O zero-value permissivo aqui significa
	// "não deduza".
	if plat.Capable().RoutedTransit {
		return Uplink{}
	}
	if plat.Facts.Net.PrimaryInterface == "" {
		return Uplink{}
	}
	return Uplink{
		Interface: plat.Facts.Net.PrimaryInterface,
		// PathMTU e NÃO LinkMTU. Copiar a MTU da placa para cá seria o bug que
		// mssclamp.go descreve: um ajuste de MSS para 8960 num caminho de 1500
		// é pior do que nenhum, porque parece feito.
		PathMTU:   plat.Facts.Net.PathMTU,
		Implicito: true,
	}
}

// uplinkEfetivo resolve a precedência: O CADASTRO VENCE, SEMPRE.
//
// Um link habilitado com interface é decisão explícita do admin, e o implícito
// não pode competir com ela nem somar-se a ela. Lista não-vazia de links ⇒
// zero-value, e os geradores seguem pelo caminho de sempre.
//
// Erro de leitura do banco também devolve zero-value, e aqui isso é o lado
// SEGURO: um SELECT que falhou não é prova de que não há link cadastrado, e
// deduzir um uplink por causa dele poria NAT numa caixa que já tem o seu.
// Quem precisa que o erro viaje é wansEfetivas — ver lá.
func uplinkEfetivo(db *storage.DB, plat platform.Snapshot) Uplink {
	ifaces, err := linksHabilitados(db)
	if err != nil {
		slog.Warn("não foi possível ler os links para decidir o uplink; nenhum uplink implícito é derivado", "err", err)
		return Uplink{}
	}
	if len(ifaces) > 0 {
		return Uplink{}
	}
	return uplinkDaPlataforma(plat)
}

// wansEfetivas é A LISTA — a única derivação de "quais são as WANs desta
// máquina" que o produto tem.
//
// Substitui as quatro cópias do mesmo laço que existiam em main.go (duas),
// internal/api/handlers/helpers.go e internal/monitoring/driftchecks.go. Quatro
// cópias de um filtro são quatro chances de o dia em que ele mudar alcançar só
// três lugares; e é justamente aqui que ele muda, porque é esta função que
// aprendeu a plataforma.
//
// ERRO DE LEITURA PROPAGA E NÃO VIRA LISTA VAZIA. Obedecer a uma lista vazia
// que na verdade é um SELECT que falhou apagaria a proteção de entrada de uma
// caixa que a tem, e o painel continuaria dizendo que ela está protegida. É o
// contrato que internal/nftables/policy.go já declara para a fonte de WANs.
func wansEfetivas(db *storage.DB, plat platform.Snapshot) ([]string, error) {
	ifaces, err := linksHabilitados(db)
	if err != nil {
		return nil, fmt.Errorf("ler os links para derivar as WANs desta máquina: %w", err)
	}
	if len(ifaces) > 0 {
		return ifaces, nil
	}
	if u := uplinkDaPlataforma(plat); u.Interface != "" {
		return []string{u.Interface}, nil
	}
	// NENHUMA DAS DUAS FONTES RESPONDEU: lista vazia, e lista vazia é o que
	// mantém ReconcileMasquerade se recusando a tocar na chain de NAT. É o
	// estado de uma caixa on-prem recém-instalada, e ele não muda.
	return nil, nil
}

// linksHabilitados é o filtro de sempre — link ligado, com interface —, agora
// escrito uma vez só.
func linksHabilitados(db *storage.DB) ([]string, error) {
	ls, err := db.GetLinks()
	if err != nil {
		return nil, err
	}
	ifaces := make([]string, 0, len(ls))
	for _, l := range ls {
		if l.Enabled && l.Interface != "" {
			ifaces = append(ifaces, l.Interface)
		}
	}
	return ifaces, nil
}

// uplinkParaTela traduz o uplink efetivo no que o painel mostra.
//
// TRADUZ AQUI, e não no handler: quem sabe casar o instantâneo da plataforma
// com o banco é este arquivo, e a camada HTTP não pode importar
// internal/platform só para nomear a plataforma numa frase de tela.
//
// As três origens são DISTINTAS na tela, e a diferença importa para quem está
// diagnosticando: "platform" explica por que a máquina sai para a Internet sem
// nenhum link cadastrado; "link" diz que quem manda é o cadastro; "none" é a
// caixa que de fato não tem saída configurada, e é o único dos três em que o
// operador tem trabalho a fazer.
func uplinkParaTela(db *storage.DB, plat platform.Snapshot) handlers.UplinkView {
	nome := string(plat.Facts.Kind)
	if nome == "" {
		nome = string(platform.KindUnknown)
	}
	v := handlers.UplinkView{Origem: handlers.UplinkOrigemNenhuma, Plataforma: nome}

	if u := uplinkEfetivo(db, plat); u.Interface != "" {
		v.Interface = u.Interface
		v.PathMTU = u.PathMTU
		v.Implicito = u.Implicito
		v.Origem = handlers.UplinkOrigemPlataforma
		return v
	}

	// Sem implícito, ou o admin cadastrou (e o cadastro vence), ou não há nada.
	// wansEfetivas responde as duas com a mesma leitura que o firewall usa.
	ifaces, err := wansEfetivas(db, plat)
	if err != nil {
		// Erro de leitura NÃO vira "não há uplink": a tela diria que a máquina
		// está sem saída por causa de um SELECT que falhou. Origem fica em
		// "none" com interface vazia, que é o honesto "não sei responder
		// agora", e o log diz por quê.
		slog.Warn("não foi possível derivar o uplink para a tela", "err", err)
		return v
	}
	if len(ifaces) > 0 {
		v.Interface = ifaces[0]
		v.Origem = handlers.UplinkOrigemLink
	}
	return v
}
