package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

type product struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Price int    `json:"price_cents"`
}

type server struct {
	db *sql.DB
}

func clampLimit(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 20
	}
	if n > 100 {
		return 100
	}
	return n
}

func (s *server) listProducts(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	limit := clampLimit(r.URL.Query().Get("limit"))
	query := fmt.Sprintf("SELECT id, name, price FROM products WHERE category = '%s' LIMIT %d", category, limit)
	rows, err := s.db.Query(query)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []product{}
	for rows.Next() {
		var p product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price); err != nil {
			http.Error(w, "scan failed", http.StatusInternalServerError)
			return
		}
		out = append(out, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func main() {
	db, err := sql.Open("fixture", "file:products.db")
	if err != nil {
		log.Fatal(err)
	}
	s := &server{db: db}
	http.HandleFunc("/products", s.listProducts)
	log.Fatal(http.ListenAndServe("127.0.0.1:8090", nil))
}
