package main

import "testing"

func TestDepositAndBalance(t *testing.T) {
	l := NewLedger()
	l.Deposit("a", 500)
	l.Deposit("a", 250)
	if got, ok := l.Balance("a"); !ok || got != 750 {
		t.Fatalf("Balance = %d, %v; want 750, true", got, ok)
	}
}

func TestWithdrawRejectsOverdraft(t *testing.T) {
	l := NewLedger()
	l.Deposit("a", 100)
	if err := l.Withdraw("a", 500); err != errInsufficient {
		t.Fatalf("Withdraw error = %v, want errInsufficient", err)
	}
	if err := l.Withdraw("missing", 1); err != errUnknownAccount {
		t.Fatalf("Withdraw error = %v, want errUnknownAccount", err)
	}
}
