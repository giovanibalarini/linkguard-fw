package updater

// A lista de releases que alimenta a tela "Novidades" do painel.
//
// POR QUE ISTO EXISTE. A tela era desenhada a partir de web/src/data/changelog.ts,
// um arquivo curado à mão — e ele parou na 1.0.82 enquanto o produto chegava à
// 1.0.110. Vinte e oito versões sem uma linha, e o admin que abrisse "Novidades"
// depois de atualizar via um painel afirmando que nada tinha mudado desde julho.
//
// Arquivo curado atrasa porque depende de alguém lembrar, e lembrar é a parte
// que falha. As notas de release, desde a issue #63, saem do próprio histórico
// de commits no workflow de publicação: elas não têm como ficar para trás. Esta
// é a mesma fonte, lida pelo produto.
//
// POR QUE AQUI, e não num pacote novo: este arquivo reaproveita o cliente HTTP
// autenticado, o token e a constante `repo` que o updater já mantém para
// checar atualização. Um segundo lugar falando com a API do GitHub seria um
// segundo lugar para o token vazar e para o rate limit ser estourado.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ReleaseNote é uma release como a tela precisa dela.
//
// Body é o markdown gerado por scripts/release-notes.sh — quem separa em
// seções é o painel, que sabe desenhar cada tipo. Manter o texto cru aqui é
// deliberado: se o formato da nota mudar, quem se adapta é a tela, e não um
// parser no meio do caminho que precisaria ser mantido em dia com ela.
type ReleaseNote struct {
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	Prerelease  bool   `json:"prerelease"`
}

// releasesPerPage é quanto se pede ao GitHub de uma vez.
//
// Trinta cobre com folga o que um admin rola numa tela de novidades, e evita
// tanto páginas adicionais quanto trazer o histórico inteiro do projeto por
// causa de uma visita ao painel.
const releasesPerPage = 30

// Releases devolve as releases publicadas, da mais nova para a mais antiga.
//
// Rascunhos são descartados: eles existem para quem publica, não para quem
// opera o firewall. Pré-lançamentos passam com a marca, para a tela decidir.
func (s *Service) Releases(ctx context.Context) ([]ReleaseNote, error) {
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=%d", s.apiBase, repo, releasesPerPage)
	resp, err := s.client.Do(s.authReq(ctx, url, "application/vnd.github+json"))
	if err != nil {
		return nil, fmt.Errorf("consultar as releases no GitHub: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // leitura
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub respondeu %d ao listar releases", resp.StatusCode)
	}

	var raw []struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		PublishedAt string `json:"published_at"`
		HTMLURL     string `json:"html_url"`
		Body        string `json:"body"`
		Draft       bool   `json:"draft"`
		Prerelease  bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("interpretar a resposta de releases do GitHub: %w", err)
	}

	out := make([]ReleaseNote, 0, len(raw))
	for _, r := range raw {
		if r.Draft {
			continue
		}
		out = append(out, ReleaseNote{
			Tag:         r.TagName,
			Name:        r.Name,
			PublishedAt: r.PublishedAt,
			HTMLURL:     r.HTMLURL,
			Body:        r.Body,
			Prerelease:  r.Prerelease,
		})
	}
	return out, nil
}
