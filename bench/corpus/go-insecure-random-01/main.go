package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const tokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type resetEntry struct {
	email   string
	expires time.Time
}

type resetTable struct {
	mu      sync.Mutex
	pending map[string]resetEntry
}

var table = &resetTable{pending: make(map[string]resetEntry)}

func newResetToken(n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = tokenAlphabet[rand.Intn(len(tokenAlphabet))]
	}
	return string(buf)
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	token := newResetToken(32)
	table.mu.Lock()
	table.pending[token] = resetEntry{email: email, expires: time.Now().Add(30 * time.Minute)}
	table.mu.Unlock()
	fmt.Fprintln(w, "if the account exists, a reset link has been sent")
}

func main() {
	http.HandleFunc("/password-reset", resetHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8096", nil))
}
