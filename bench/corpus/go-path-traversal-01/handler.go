package main

import (
	"log"
	"net/http"
	"strings"
)

type api struct {
	docs *DocStore
}

func requestedDocument(r *http.Request) string {
	name := r.URL.Query().Get("name")
	return strings.TrimSpace(name)
}

func (a *api) download(w http.ResponseWriter, r *http.Request) {
	name := requestedDocument(r)
	data, err := a.docs.Load(name)
	if err != nil {
		http.Error(w, "document not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType(name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}

func main() {
	a := &api{docs: NewDocStore("/var/lib/docs")}
	http.HandleFunc("/download", a.download)
	log.Fatal(http.ListenAndServe("127.0.0.1:8092", nil))
}
