package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type lookupResult struct {
	Host    string
	Output  string
	Elapsed time.Duration
}

func resolve(host string) (lookupResult, error) {
	start := time.Now()
	cmd := exec.Command("sh", "-c", "nslookup "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return lookupResult{}, fmt.Errorf("lookup failed: %w", err)
	}
	return lookupResult{Host: host, Output: strings.TrimSpace(string(out)), Elapsed: time.Since(start)}, nil
}

func lookupHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	res, err := resolve(host)
	if err != nil {
		http.Error(w, "lookup failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "%s (%s)\n%s\n", res.Host, res.Elapsed.Round(time.Millisecond), res.Output)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", lookupHandler)
	srv := &http.Server{Addr: "127.0.0.1:8091", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
