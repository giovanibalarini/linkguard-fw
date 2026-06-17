package handlers

import (
"encoding/json"
"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(status)
_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v interface{}) error {
return json.NewDecoder(r.Body).Decode(v)
}
