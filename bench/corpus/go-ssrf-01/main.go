package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var client = &http.Client{Timeout: 5 * time.Second}

type statusProbe struct {
	scheme string
	port   int
	path   string
}

var defaultProbe = statusProbe{scheme: "http", port: 8500, path: "/v1/status"}

func (p statusProbe) endpoint(node string) string {
	return fmt.Sprintf("%s://%s:%d%s", p.scheme, node, p.port, p.path)
}

func nodeStatus(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	if node == "" {
		http.Error(w, "node is required", http.StatusBadRequest)
		return
	}
	target := defaultProbe.endpoint(node)
	log.Printf("probing node status")
	w.Header().Set("Content-Type", "application/json")
	resp, err := client.Get(target)
	if err != nil {
		http.Error(w, "node unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/node-status", nodeStatus)
	srv := &http.Server{Addr: "127.0.0.1:8093", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
