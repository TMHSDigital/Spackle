package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var docRoot = filepath.Clean("/var/www/help")

var allowedUnits = map[string]bool{"nginx.service": true, "worker.service": true, "cron.service": true}

type app struct {
	db *sql.DB
}

func (a *app) productName(sku string) (string, error) {
	var name string
	err := a.db.QueryRow("SELECT name FROM products WHERE sku = ?", sku).Scan(&name)
	return name, err
}

func unitStatus(unit string) ([]byte, error) {
	if !allowedUnits[unit] {
		return nil, errors.New("unit not allowed")
	}
	return exec.Command("systemctl", "is-active", unit).Output()
}

func safeDocPath(name string) (string, error) {
	full := filepath.Clean(filepath.Join(docRoot, name))
	if !strings.HasPrefix(full, docRoot+string(os.PathSeparator)) {
		return "", errors.New("path escapes document root")
	}
	return full, nil
}

func (a *app) productHandler(w http.ResponseWriter, r *http.Request) {
	name, err := a.productName(r.URL.Query().Get("sku"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, name)
}

func unitHandler(w http.ResponseWriter, r *http.Request) {
	out, err := unitStatus(r.URL.Query().Get("unit"))
	if err != nil {
		http.Error(w, "status unavailable", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(out)
}

func docHandler(w http.ResponseWriter, r *http.Request) {
	path, err := safeDocPath(r.URL.Query().Get("name"))
	if err != nil {
		http.Error(w, "bad document name", http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(data)
}

func main() {
	db, err := sql.Open("fixture", "file:catalog.db")
	if err != nil {
		log.Fatal(err)
	}
	a := &app{db: db}
	http.HandleFunc("/product", a.productHandler)
	http.HandleFunc("/unit", unitHandler)
	http.HandleFunc("/doc", docHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8097", nil))
}
