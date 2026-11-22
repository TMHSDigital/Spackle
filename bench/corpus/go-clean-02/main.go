package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

var allowedHosts = map[string]bool{"status.example.com": true, "api.example.com": true}

var client = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func fetchAllowed(raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		return nil, errors.New("destination not allowed")
	}
	resp, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	if !validAPIKey(r.Header.Get("X-Api-Key")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := fetchAllowed(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, "fetch failed", http.StatusBadGateway)
		return
	}
	tag := etag(body)
	if r.Header.Get("If-None-Match") == tag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", tag)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(body)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if !validAPIKey(r.Header.Get("X-Api-Key")) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := newToken()
	if err != nil {
		http.Error(w, "token unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(token + "\n"))
}

func main() {
	http.HandleFunc("/proxy", proxyHandler)
	http.HandleFunc("/token", tokenHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8098", nil))
}
