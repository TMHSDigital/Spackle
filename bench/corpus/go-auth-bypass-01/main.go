package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

type flagStore struct {
	mu    sync.Mutex
	flags map[string]bool
}

var store = &flagStore{flags: map[string]bool{"new-checkout": false, "beta-search": true}}

func isAdmin(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	want := os.Getenv("ADMIN_TOKEN")
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

func flagsHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if r.Method == http.MethodPost && !isAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		store.flags[name] = r.URL.Query().Get("enabled") == "true"
	case http.MethodDelete:
		delete(store.flags, name)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(store.flags)
}

func main() {
	http.HandleFunc("/flags", flagsHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8095", nil))
}
