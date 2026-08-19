package nftables

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTodoRuleOwnerKeyTemTraducao amarra este pacote ao dicionário do painel
// (issue #106).
//
// O backend manda `owner.key` + `owner.label`, e a tela traduz A PARTIR DO KEY —
// o label continua vindo em português porque ele também vai para log, auditoria
// e resposta de API, onde não existe idioma de sessão.
//
// A consequência é que acrescentar um RuleOwner novo aqui, sem acrescentar a
// chave no YAML, faz a tela imprimir o id cru ("fwx.owner.vpn") no lugar do
// nome do dono da regra. Nada quebra, nada avisa: só fica feio para o operador,
// e provavelmente só em inglês, que é onde menos gente olha.
//
// Este teste lê o classify.go de verdade e o YAML de verdade. É de TEXTO de
// propósito, como o TestBootPersistScreens: a garantia que ele dá não existe em
// nenhum tipo.
func TestTodoRuleOwnerKeyTemTraducao(t *testing.T) {
	src, err := os.ReadFile("classify.go")
	if err != nil {
		t.Fatalf("ReadFile classify.go: %v", err)
	}

	// Key: "algo" — a única forma que o pacote usa para declarar dono.
	re := regexp.MustCompile(`RuleOwner\{Key:\s*"([a-z_]+)"`)
	achados := re.FindAllStringSubmatch(string(src), -1)
	if len(achados) == 0 {
		t.Fatal("nenhum RuleOwner com Key encontrado; o formato mudou e esta guarda parou de guardar")
	}

	yamlPath := filepath.Join("..", "..", "web", "src", "i18n", "strings", "firewall-resto.yaml")
	dic, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", yamlPath, err)
	}
	texto := string(dic)

	vistos := map[string]bool{}
	for _, m := range achados {
		key := m[1]
		if vistos[key] {
			continue
		}
		vistos[key] = true
		if !strings.Contains(texto, "\nfwx.owner."+key+":") {
			t.Errorf("o dono %q não tem tradução: falta a chave `fwx.owner.%s` em %s.\n"+
				"Sem ela a tela imprime o id cru no lugar do nome do dono da regra.",
				key, key, yamlPath)
		}
	}
	if len(vistos) < 5 {
		t.Errorf("só %d donos encontrados; esperava a lista inteira do classify.go", len(vistos))
	}
}

// TestTodaDescKeyTemTraducao é o mesmo contrato do teste acima, para as chaves
// de DESCRIÇÃO (issue #109).
//
// A diferença de consequência: um dono sem tradução mostra o id no lugar de um
// rótulo curto; uma descrição sem tradução mostra o id no lugar da frase que
// EXPLICA a linha do firewall — que é a coluna inteira da Visão geral.
func TestTodaDescKeyTemTraducao(t *testing.T) {
	src, err := os.ReadFile("classify.go")
	if err != nil {
		t.Fatalf("ReadFile classify.go: %v", err)
	}

	re := regexp.MustCompile(`RuleDesc\{Key:\s*"([a-zA-Z0-9_.]+)"`)
	achados := re.FindAllStringSubmatch(string(src), -1)
	if len(achados) == 0 {
		t.Fatal("nenhum RuleDesc com Key encontrado; o formato mudou e esta guarda parou de guardar")
	}

	yamlPath := filepath.Join("..", "..", "web", "src", "i18n", "strings", "firewall-resto.yaml")
	dic, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", yamlPath, err)
	}
	texto := string(dic)

	vistos := map[string]bool{}
	for _, m := range achados {
		key := m[1]
		if vistos[key] {
			continue
		}
		vistos[key] = true
		// Chave terminada em "." é PEDAÇO de concatenação, não chave: o
		// userRuleDesc monta "desc.user." + ação. Conferi-la aqui acusaria uma
		// chave que nunca existe. As montadas assim estão na lista explícita
		// logo abaixo — é o preço de serem invisíveis ao regex.
		if strings.HasSuffix(key, ".") {
			continue
		}
		if !strings.Contains(texto, "\n"+key+":") {
			t.Errorf("a descrição %q não tem tradução: falta a chave `%s` em %s.\n"+
				"Sem ela a coluna de descrição da Visão geral imprime o id cru.", key, key, yamlPath)
		}
	}

	// As chaves das regras do admin são montadas por concatenação em
	// userRuleDesc ("desc.user." + ação), então o regex acima não as vê. Elas
	// são poucas e fechadas, e é justamente por serem invisíveis ao regex que
	// precisam ser listadas à mão aqui.
	for _, acao := range []string{"accept", "drop", "reject", "rule"} {
		for _, k := range []string{"desc.user." + acao, "desc.user." + acao + ".any"} {
			if !strings.Contains(texto, "\n"+k+":") {
				t.Errorf("falta a chave `%s` em %s", k, yamlPath)
			}
		}
	}
	for _, rot := range []string{"iif", "oif", "saddr", "daddr", "proto"} {
		if !strings.Contains(texto, "\ndesc.cond."+rot+":") {
			t.Errorf("falta a etiqueta `desc.cond.%s` em %s", rot, yamlPath)
		}
	}
}
