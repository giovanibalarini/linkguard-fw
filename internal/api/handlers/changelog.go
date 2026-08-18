package handlers

// A tela "Novidades" passa a ler as releases publicadas, em vez de um arquivo
// curado à mão.
//
// O arquivo (web/src/data/changelog.ts) parou na 1.0.82 enquanto o produto
// chegava à 1.0.110: vinte e oito versões sem uma linha, e quem abrisse a tela
// depois de atualizar via o painel afirmando que nada tinha mudado desde julho.
// Curadoria manual atrasa porque depende de alguém lembrar, e lembrar é a parte
// que falha. Desde a issue #63 a nota de release sai do próprio histórico de
// commits, no workflow de publicação — esta é a mesma fonte.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-fw/internal/updater"
)

// changelogCacheKey guarda a última resposta boa do GitHub.
const changelogCacheKey = "changelog_cache"

// changelogTTL é por quanto tempo o cache é servido sem perguntar de novo.
//
// Uma hora porque a informação muda no ritmo de uma release, não de um
// segundo, e porque a alternativa custa caro nos dois sentidos: sem cache,
// cada visita à tela gasta uma chamada do rate limit do GitHub e faz o painel
// esperar a rede de um firewall que pode estar com o link ruim — que é
// justamente quando o admin está olhando o painel.
const changelogTTL = time.Hour

// changelogFetchTimeout limita a espera pela rede. A tela é informativa: ela
// não pode prender uma aba por causa de um link degradado.
const changelogFetchTimeout = 10 * time.Second

type changelogCache struct {
	FetchedAt int64                 `json:"fetched_at"`
	Releases  []updater.ReleaseNote `json:"releases"`
}

type changelogResponse struct {
	Releases []updater.ReleaseNote `json:"releases"`
	// Stale diz que o que está sendo mostrado veio do cache porque a consulta
	// de agora falhou. A tela avisa em vez de apresentar como atual — um
	// painel que mente sobre a idade do que mostra é pior do que um que
	// admite estar velho.
	Stale bool `json:"stale"`
	// FetchedAt é quando a lista foi realmente obtida (unix, 0 se nunca).
	FetchedAt int64 `json:"fetched_at"`
	// Error explica por que não deu para atualizar, quando Stale é true.
	Error string `json:"error,omitempty"`
}

// Changelog devolve as releases publicadas, servindo do cache quando ele ainda
// está fresco ou quando o GitHub não responde.
//
// A ordem dos casos é a que o admin precisa:
//
//	cache fresco          → responde na hora, sem rede
//	cache velho e rede ok → atualiza e responde
//	cache velho e rede má → responde O CACHE, marcado como velho
//	sem cache e rede má   → 503 com o motivo
//
// O terceiro é o que faz esta tela servir num firewall sem internet, que é uma
// instalação legítima deste produto — e não uma exceção a tolerar.
func (h *UpdateHandler) Changelog(w http.ResponseWriter, r *http.Request) {
	cached, hasCache := h.changelogFromCache()
	if hasCache && time.Since(time.Unix(cached.FetchedAt, 0)) < changelogTTL {
		writeJSON(w, http.StatusOK, changelogResponse{
			Releases: cached.Releases, FetchedAt: cached.FetchedAt,
		})
		return
	}

	// Desligado do contexto da requisição: se o admin fechar a aba no meio, a
	// busca ainda termina e o cache é preenchido para a próxima visita.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), changelogFetchTimeout)
	defer cancel()

	releases, err := h.svc.Releases(ctx)
	if err != nil {
		if hasCache {
			slog.Warn("não foi possível atualizar as novidades; servindo o que estava em cache", "err", err)
			writeJSON(w, http.StatusOK, changelogResponse{
				Releases: cached.Releases, FetchedAt: cached.FetchedAt,
				Stale: true, Error: err.Error(),
			})
			return
		}
		slog.Warn("não foi possível buscar as novidades e não há cache", "err", err)
		writeError(w, http.StatusServiceUnavailable,
			"não foi possível buscar as novidades agora — o firewall precisa de acesso à internet para lê-las pela primeira vez")
		return
	}

	now := time.Now().Unix()
	if b, mErr := json.Marshal(changelogCache{FetchedAt: now, Releases: releases}); mErr == nil {
		// Falha ao gravar o cache não estraga a resposta: o admin recebe a
		// lista que acabou de ser buscada, e a próxima visita busca de novo.
		if sErr := h.db.SetSetting(changelogCacheKey, string(b)); sErr != nil {
			slog.Warn("não foi possível gravar o cache das novidades", "err", sErr)
		}
	}
	writeJSON(w, http.StatusOK, changelogResponse{Releases: releases, FetchedAt: now})
}

func (h *UpdateHandler) changelogFromCache() (changelogCache, bool) {
	raw, err := h.db.GetSetting(changelogCacheKey)
	if err != nil || raw == "" {
		return changelogCache{}, false
	}
	var c changelogCache
	if err := json.Unmarshal([]byte(raw), &c); err != nil || len(c.Releases) == 0 {
		return changelogCache{}, false
	}
	return c, true
}
