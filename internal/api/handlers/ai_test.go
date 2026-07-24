package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-fw/internal/ai"
	"github.com/giovanibalarini/linkguard-fw/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-fw/internal/secrets"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
)

func newAITestHandler(t *testing.T) (*handlers.AIHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	sec := secrets.NewService(db, key)
	budget := ai.NewBudgetGuard(db)
	client := ai.NewClient(sec, budget, func() ai.Config { return ai.LoadConfig(db) })
	return handlers.NewAIHandler(db, sec, client), db
}

func TestAIStatusNeverReturnsTheToken(t *testing.T) {
	h, db := newAITestHandler(t)
	dir := t.TempDir()
	key, _ := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	sec := secrets.NewService(db, key)
	_ = sec.Set("ai_api_token", "sk-ant-realsecretvalue")

	req := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w := httptest.NewRecorder()
	h.Status(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if bytesContain(w.Body.Bytes(), []byte("sk-ant-realsecretvalue")) {
		t.Fatal("SECURITY: /api/ai/status leaked the raw token value")
	}
}

func TestSetTokenThenStatusShowsConfigured(t *testing.T) {
	h, _ := newAITestHandler(t)

	body, _ := json.Marshal(map[string]string{"token": "sk-ant-abcd1234wxyz7f2a"})
	req := httptest.NewRequest(http.MethodPut, "/api/ai/token", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.SetToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("SetToken: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w2 := httptest.NewRecorder()
	h.Status(w2, req2)

	var resp struct {
		Configured bool   `json:"configured"`
		Hint       string `json:"hint"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Configured {
		t.Fatal("expected configured=true after SetToken")
	}
	if resp.Hint != "sk-ant-…7f2a" {
		t.Fatalf("expected hint sk-ant-…7f2a, got %q", resp.Hint)
	}
}

func TestDeleteTokenClearsConfigured(t *testing.T) {
	h, _ := newAITestHandler(t)

	body, _ := json.Marshal(map[string]string{"token": "sk-ant-abcd"})
	req := httptest.NewRequest(http.MethodPut, "/api/ai/token", bytes.NewReader(body))
	h.SetToken(httptest.NewRecorder(), req)

	delReq := httptest.NewRequest(http.MethodDelete, "/api/ai/token", nil)
	delW := httptest.NewRecorder()
	h.DeleteToken(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("DeleteToken: expected 200, got %d", delW.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/ai/status", nil)
	w2 := httptest.NewRecorder()
	h.Status(w2, req2)
	var resp struct {
		Configured bool `json:"configured"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp.Configured {
		t.Fatal("expected configured=false after DeleteToken")
	}
}

func bytesContain(haystack, needle []byte) bool {
	return len(haystack) >= len(needle) && string(haystack) != "" &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if string(haystack[i:i+len(needle)]) == string(needle) {
					return true
				}
			}
			return false
		})()
}
