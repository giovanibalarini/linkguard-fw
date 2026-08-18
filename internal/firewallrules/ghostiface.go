package firewallrules

// Interfaces que as regras citam e que não existem mais (issue #83).
//
// O PROBLEMA. Todo `iifname`/`oifname` deste projeto casa por NOME, nunca por
// índice. E um nome que não existe carrega no nft SEM ERRO — a regra entra no
// ruleset, o painel a mostra ativa, e ela simplesmente nunca casa com pacote
// nenhum.
//
// Isso não é hipótese. Está registrado em reconcile.go:26-28: em produção, em
// 2026-08-10, uma NIC foi renomeada por um reshuffle de PCI (enp4s0 → enp5s0).
// Toda regra que a citava virou decoração naquele boot, e nada avisou.
//
// A assimetria é o que torna o defeito cruel: uma regra de ACCEPT que deixa de
// casar só faz o tráfego cair em outra linha — chato. Uma regra de DROP que
// deixa de casar é uma proteção que sumiu, com o painel afirmando que ela está
// lá. É a confiança falsa que este produto existe para eliminar.
//
// O QUE ESTA PEÇA FAZ, E O QUE ELA NÃO FAZ. Ela só COMPARA duas listas e diz o
// que não bate. Não corrige a regra (renomear por conta própria seria adivinhar
// qual interface o admin queria), não a desativa (desativar silenciosamente uma
// regra de bloqueio é o mesmo defeito com outro nome), e não impede o boot.
//
// Ela existe para o produto poder AVISAR — que é a única resposta honesta a uma
// pergunta cuja resposta certa só o admin tem.

import "sort"

// GhostIface é uma interface citada por configuração e ausente da máquina.
type GhostIface struct {
	// Name é o nome citado, como está gravado.
	Name string
	// Groups são os nomes dos grupos que a citam na condição de entrada.
	Groups []string
	// Rules é quantas regras a citam em iif/oif.
	Rules int
	// Blocking diz se ALGUMA das regras que a citam bloqueia (drop/reject).
	//
	// É o campo que decide a gravidade: uma regra de accept que não casa é
	// chateação; uma de drop que não casa é uma proteção que não existe mais.
	Blocking bool
}

// IfaceRef é uma citação de interface, vinda de um grupo ou de uma regra.
type IfaceRef struct {
	// Name é a interface citada. Vazio é ignorado (significa "qualquer").
	Name string
	// GroupName preenchido marca a citação como sendo da condição de um grupo.
	GroupName string
	// Action é a ação da regra que cita, quando a citação vem de uma regra.
	Action string
}

// FindGhostIfaces devolve as interfaces citadas que não estão entre as vivas.
//
// A comparação é EXATA e sensível a caixa, de propósito: nomes de interface no
// Linux são case-sensitive, e "aproximar" aqui produziria um falso negativo —
// dizer que está tudo bem quando a regra não casa — que é o pior dos dois erros
// possíveis nesta função.
//
// A saída é ordenada por nome para o alerta ser estável: um alerta cujo texto
// muda de ordem a cada passada vira ruído e deixa de ser lido.
func FindGhostIfaces(refs []IfaceRef, vivas []string) []GhostIface {
	existe := make(map[string]bool, len(vivas))
	for _, v := range vivas {
		if v != "" {
			existe[v] = true
		}
	}
	// Sem NENHUMA interface viva, a resposta é "não sei", não "todas sumiram".
	// Uma leitura que falhou e devolveu lista vazia geraria um alerta dizendo
	// que a máquina inteira é fantasma — e o alerta que grita por tudo é o que
	// ninguém mais lê.
	if len(existe) == 0 {
		return nil
	}

	porNome := map[string]*GhostIface{}
	for _, r := range refs {
		if r.Name == "" || existe[r.Name] {
			continue
		}
		g := porNome[r.Name]
		if g == nil {
			g = &GhostIface{Name: r.Name}
			porNome[r.Name] = g
		}
		if r.GroupName != "" {
			g.Groups = append(g.Groups, r.GroupName)
			continue
		}
		g.Rules++
		if r.Action == "drop" || r.Action == "reject" {
			g.Blocking = true
		}
	}

	out := make([]GhostIface, 0, len(porNome))
	for _, g := range porNome {
		sort.Strings(g.Groups)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AnyBlocking diz se alguma das fantasmas era usada para bloquear. É o que
// separa um aviso de uma condição crítica.
func AnyBlocking(gs []GhostIface) bool {
	for _, g := range gs {
		if g.Blocking {
			return true
		}
	}
	return false
}
