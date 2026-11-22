package main

import (
	"errors"
	"sync"
)

var errInsufficient = errors.New("insufficient funds")
var errUnknownAccount = errors.New("unknown account")

type Ledger struct {
	mu       sync.RWMutex
	balances map[string]int64
}

func NewLedger() *Ledger {
	return &Ledger{balances: make(map[string]int64)}
}

func (l *Ledger) Deposit(account string, cents int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.balances[account] += cents
}

func (l *Ledger) Balance(account string) (int64, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	v, ok := l.balances[account]
	return v, ok
}

func (l *Ledger) Withdraw(account string, cents int64) error {
	balance, ok := l.Balance(account)
	if !ok {
		return errUnknownAccount
	}
	if balance < cents {
		return errInsufficient
	}
	l.mu.Lock()
	l.balances[account] -= cents
	l.mu.Unlock()
	return nil
}
