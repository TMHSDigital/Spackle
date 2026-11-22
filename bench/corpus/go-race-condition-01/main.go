package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
)

var ledger = NewLedger()

func withdrawHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	account := r.FormValue("account")
	cents, err := strconv.ParseInt(r.FormValue("cents"), 10, 64)
	if err != nil || cents <= 0 {
		http.Error(w, "invalid amount", http.StatusBadRequest)
		return
	}
	if err := ledger.Withdraw(account, cents); err != nil {
		http.Error(w, "withdrawal rejected", http.StatusConflict)
		return
	}
	balance, _ := ledger.Balance(account)
	fmt.Fprintf(w, "ok balance=%d\n", balance)
}

func main() {
	ledger.Deposit("acct-1001", 50000)
	http.HandleFunc("/withdraw", withdrawHandler)
	log.Fatal(http.ListenAndServe("127.0.0.1:8094", nil))
}
