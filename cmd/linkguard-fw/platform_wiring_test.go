package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// Este arquivo guarda a POSIÇÃO da detecção de plataforma dentro de run(), que
// é uma ligação que nenhum teste de pacote enxerga.
//
// As duas metades da ordem são obrigatórias por motivos diferentes:
//
//   - depois de openStore, porque o instantâneo é cacheado na tabela settings
//     e antes daquela linha não existe banco;
//   - antes de buildServices, porque é lá que toda ligação entre serviços
//     mora, por decisão argumentada (ver o doc-comment daquela função). Detectar
//     depois obrigaria a um SetPlatform tardio — exatamente a "ligação opcional
//     e silenciosa" que aquele comentário recusa.
//
// E a detecção NÃO PODE descer para provisionSystem: aquela função só roda
// depois de bootstrapdeps.Ensure, que num link ruim leva meia hora. Um fato
// que os outros serviços consultam não pode nascer atrás de uma espera dessas.
//
// A verificação é feita sobre a árvore sintática, e não por busca de texto,
// para não depender de comentários que citem os mesmos nomes.
func TestPlatformIsDetectedBetweenTheStoreAndTheServices(t *testing.T) {
	file := parseMainGo(t)

	run := funcDecl(t, file, "run")

	pos := map[string]int{}
	ast.Inspect(run, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		ident, isIdent := call.Fun.(*ast.Ident)
		if !isIdent {
			return true
		}
		if _, already := pos[ident.Name]; !already {
			pos[ident.Name] = int(call.Pos())
		}
		return true
	})

	for _, nome := range []string{"openStore", "detectPlatformOnBoot", "buildServices"} {
		if _, found := pos[nome]; !found {
			t.Fatalf("run() não chama mais %s -- se a sequência de boot mudou de forma, este guarda precisa mudar junto", nome)
		}
	}

	if pos["openStore"] > pos["detectPlatformOnBoot"] {
		t.Error("detectPlatformOnBoot tem que vir DEPOIS de openStore: o instantâneo de plataforma é cacheado na tabela settings, e antes do openStore não há banco para ler nem para gravar")
	}
	if pos["detectPlatformOnBoot"] > pos["buildServices"] {
		t.Error("detectPlatformOnBoot tem que vir ANTES de buildServices: é buildServices que monta e liga os serviços, e detectar depois obrigaria a um SetPlatform tardio -- a ligação opcional e silenciosa que aquela função existe para não ter")
	}
}

// TestBuildServicesReceivesTheDetectedPlatform afirma que o resultado da
// detecção CHEGA na montagem.
//
// Sem isto, a chamada poderia continuar na ordem certa e o valor ser jogado
// fora — o boot subiria, os testes ficariam verdes, e o produto se comportaria
// como se estivesse sempre numa máquina genérica. É a mesma classe de falha
// silenciosa que boot_order_test.go guarda para a chain input.
func TestBuildServicesReceivesTheDetectedPlatform(t *testing.T) {
	file := parseMainGo(t)
	run := funcDecl(t, file, "run")

	// Nome da variável que recebeu o resultado de detectPlatformOnBoot.
	var destino string
	ast.Inspect(run, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "detectPlatformOnBoot" {
			return true
		}
		if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
			destino = lhs.Name
		}
		return false
	})
	if destino == "" {
		t.Fatal("o resultado de detectPlatformOnBoot não é atribuído a nada em run(): a plataforma detectada está sendo descartada")
	}

	passado := false
	ast.Inspect(run, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); !ok || ident.Name != "buildServices" {
			return true
		}
		for _, arg := range call.Args {
			if ident, ok := arg.(*ast.Ident); ok && ident.Name == destino {
				passado = true
			}
		}
		return true
	})
	if !passado {
		t.Errorf("buildServices não recebe %q: a plataforma é detectada e descartada, e o produto se comporta como se toda máquina fosse genérica", destino)
	}
}

// TestPlatformDetectionIsNotBehindTheDependencyInstall guarda a armadilha do
// meia-hora.
//
// provisionSystem é um closure DENTRO de startBackground, e só é alcançado
// depois de bootstrapdeps.Ensure — que num link ruim leva meia hora
// (main.go documenta o caso). Olhar startBackground inteira cobre o closure
// junto, que é o que interessa: um fato consultado pelos outros serviços não
// pode nascer atrás daquela espera.
func TestPlatformDetectionIsNotBehindTheDependencyInstall(t *testing.T) {
	file := parseMainGo(t)
	fn := funcDecl(t, file, "startBackground")

	ast.Inspect(fn, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "detectPlatformOnBoot" {
			t.Error("detectPlatformOnBoot foi chamada de dentro de startBackground: ali a detecção fica atrás de bootstrapdeps.Ensure, que num link ruim leva meia hora, e os serviços montados por buildServices já teriam decidido tudo sem ela")
		}
		return true
	})
}

func parseMainGo(t *testing.T) *ast.File {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(filepath.Dir(thisFile), "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}
	return file
}

func funcDecl(t *testing.T, file *ast.File, nome string) *ast.FuncDecl {
	t.Helper()
	for _, d := range file.Decls {
		fn, isFunc := d.(*ast.FuncDecl)
		if isFunc && fn.Recv == nil && fn.Name.Name == nome {
			return fn
		}
	}
	t.Fatalf("main.go não tem mais a função %s -- se a sequência de boot mudou de forma, este guarda precisa mudar junto", nome)
	return nil
}
