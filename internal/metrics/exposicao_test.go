package metrics

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestNenhumaSerieDeAparelhoNoRegistroAberto é a rede que impede o defeito que
// as issues #115, #117 e #118 criariam juntas.
//
// O /metrics está registrado FORA do grupo autenticado e a suíte exige que ele
// responda pela WAN. Uma série com rótulo de aparelho ali é inventário da rede
// do cliente publicado sem senha — e nenhuma das três issues, sozinha, tem como
// perceber isso, porque não há arquivo em comum entre elas.
//
// ELE VARRE DESCRITORES, E NÃO AMOSTRAS, e essa é a diferença entre medir e não
// medir nada. Gather() OMITE um GaugeVec sem filhos, e num registro recém-criado
// nenhum vec tem filho: pela via das amostras, as famílias com rótulo
// (link_status{link,interface}, interface_rx_bytes_total{interface}, …)
// simplesmente não aparecem, o laço de rótulos nunca executa uma iteração, e
// registrar linkguard_host_bytes_total como GaugeVec passaria verde enquanto a
// caixa em produção publica todo aparelho da LAN sem senha.
//
// Describe() não tem esse buraco: o descritor existe desde o registro, e já
// carrega nome E lista de rótulos antes de existir qualquer amostra.
func TestNenhumaSerieDeAparelhoNoRegistroAberto(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	descs := descritoresDe(t, m)
	if len(descs) == 0 {
		t.Fatal("nenhum descritor colhido: este teste não estaria medindo nada")
	}
	comRotulo := 0
	for _, d := range descs {
		nome, rotulos := leDescritor(t, d)
		if SerieDeAparelho(nome) {
			t.Errorf("a série %q carrega identidade de aparelho e está no /metrics, que é aberto", nome)
		}
		if len(rotulos) > 0 {
			comRotulo++
		}
		for _, r := range rotulos {
			if RotuloDeAparelho(r) {
				t.Errorf("a série %q tem rótulo %q: identidade de aparelho no /metrics aberto", nome, r)
			}
		}
	}
	// A metade "o vazamento seria pelo rótulo" tem de ter olhado para
	// alguma coisa. Se nenhum descritor tiver rótulo variável, o parser quebrou
	// (o formato do Desc.String mudou) e o teste virou decoração.
	if comRotulo == 0 {
		t.Fatal("nenhum descritor com rótulo variável: o parser de Desc não está lendo os rótulos")
	}
}

// TestGatherTambemNaoPublicaIdentidade é a segunda camada: descritor cobre o que
// está registrado, amostra cobre o que de fato sai pelo fio.
func TestGatherTambemNaoPublicaIdentidade(t *testing.T) {
	reg := prometheus.NewRegistry()
	New(reg)
	familias, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range familias {
		if SerieDeAparelho(f.GetName()) {
			t.Errorf("a série %q carrega identidade de aparelho e está no /metrics", f.GetName())
		}
		for _, mt := range f.GetMetric() {
			for _, l := range mt.GetLabel() {
				if RotuloDeAparelho(l.GetName()) {
					t.Errorf("a série %q tem rótulo %q no /metrics aberto", f.GetName(), l.GetName())
				}
			}
		}
	}
}

// descritoresDe colhe o descritor de cada coletor de *Metrics.
//
// Por reflexão sobre os campos, e não por uma lista escrita à mão: uma lista
// escrita à mão é exatamente o lugar onde alguém esquece de acrescentar a
// métrica nova — que é o esquecimento que este arquivo existe para pegar.
func descritoresDe(t *testing.T, m *Metrics) []*prometheus.Desc {
	t.Helper()
	v := reflect.ValueOf(m).Elem()
	var out []*prometheus.Desc
	for i := 0; i < v.NumField(); i++ {
		c, ok := v.Field(i).Interface().(prometheus.Collector)
		if !ok {
			t.Fatalf("o campo %s de Metrics não é um prometheus.Collector — este teste deixaria de vê-lo",
				v.Type().Field(i).Name)
		}
		ch := make(chan *prometheus.Desc, 16)
		go func() {
			c.Describe(ch)
			close(ch)
		}()
		for d := range ch {
			out = append(out, d)
		}
	}
	return out
}

var reNome = regexp.MustCompile(`fqName: "(.+?)"`)

// leDescritor extrai nome e rótulos variáveis do Desc.
//
// Pelo texto do Desc.String() porque os campos são privados e não há outro
// caminho público. O teste acima verifica que o parser continua achando
// rótulos: se o formato mudar numa atualização do client_golang, ele grita em
// vez de passar em branco.
func leDescritor(t *testing.T, d *prometheus.Desc) (string, []string) {
	t.Helper()
	s := d.String()
	mn := reNome.FindStringSubmatch(s)
	if mn == nil {
		t.Fatalf("não consegui ler o nome do descritor %q", s)
	}
	return mn[1], rotulosDe(s)
}

const marcaRotulos = "variableLabels: "

// rotulosDe recorta a lista de rótulos variáveis sem regexp de classe.
//
// O client_golang já imprimiu essa lista entre chaves e entre colchetes em
// versões diferentes, e um parser que só conhece uma das duas formas passa em
// branco na outra — que é o modo de falha silencioso que este arquivo existe
// para não ter. Por isso as duas aberturas e os dois fechamentos.
func rotulosDe(s string) []string {
	i := strings.Index(s, marcaRotulos)
	if i < 0 {
		return nil
	}
	resto := s[i+len(marcaRotulos):]
	corte := strings.TrimLeft(resto, aberturas)
	if corte == resto {
		return nil // nem chave nem colchete: formato desconhecido
	}
	j := strings.IndexAny(corte, fechamentos)
	if j < 0 {
		return nil
	}
	var out []string
	for _, r := range strings.Split(corte[:j], virgula) {
		r = strings.TrimSpace(r)
		r = strings.Trim(r, aspas)
		if r != vazio {
			out = append(out, r)
		}
	}
	return out
}

// As duas grafias que o client_golang já usou para imprimir a lista de
// rótulos, e o que separa e envolve cada nome dentro dela. Constantes porque
// escrever esses caracteres soltos no meio do parser é como se perde a segunda
// grafia numa atualização de dependência.
const (
	aberturas   = "{["
	fechamentos = "}]"
	virgula     = ","
	aspas       = "\"'`"
	vazio       = ""
)

func TestSerieDeAparelhoReconheceOsPrefixos(t *testing.T) {
	for _, s := range []string{
		"linkguard_host_rx_bytes", "linkguard_device_seen", "linkguard_client_x",
		// O vizinho de colisão quase-perfeita: o pacote da cota chama-se
		// hostquota, e "linkguard_hostquota_" NÃO começa por
		// "linkguard_host_" — a posição 15 é um q, não um sublinhado.
		"linkguard_hostquota_used_bytes", "linkguard_cota_usada",
	} {
		if !SerieDeAparelho(s) {
			t.Errorf("%q devia ser reconhecida como identidade de aparelho", s)
		}
	}
	for _, s := range []string{"linkguard_alerts_unresolved_total", "linkguard_links_total", "linkguard_system_uptime_seconds"} {
		if SerieDeAparelho(s) {
			t.Errorf("%q é agregado e foi tratado como identidade", s)
		}
	}
}

func TestRotuloDeAparelhoPegaOsApelidos(t *testing.T) {
	// A lista antiga era mac|host|device|aparelho. Passavam limpo justamente as
	// palavras que um autor de métrica escreve sem pensar — e um
	// linkguard_quota_used_bytes com rótulo apelido publicaria o nome que o
	// dono deu ao aparelho, sem senha.
	for _, r := range []string{"mac", "MAC", "host", "hostname", "device", "aparelho",
		"apelido", "alias", "nome", "name", "ip", "endereco", "cliente", "client"} {
		if !RotuloDeAparelho(r) {
			t.Errorf("o rótulo %q identifica um aparelho e passou pelo guarda", r)
		}
	}
	for _, r := range []string{"link", "interface", "severity", "state"} {
		if RotuloDeAparelho(r) {
			t.Errorf("o rótulo %q é agregado e foi barrado", r)
		}
	}
}
