# go-race-condition-01

Intentionally vulnerable test data for Spackle. This code is flawed on purpose
so a security scanner can be measured against it. It must never be deployed,
exposed to a network, or copied into a real project.

Ledger.Withdraw in ledger.go checks the balance under a read lock, releases it, and then deducts under a separate write lock, so concurrent withdrawals can overdraw the account.

## Planted

- `race-condition` (CWE-367) at `ledger.go` line 42, sink `Ledger.Withdraw`: balance was checked earlier under a different lock acquisition, so the check and the deduction are not atomic

## Why this is a hard case

Every map access is under a mutex, so there is no data race for a race detector or a lock-usage lint to report. The flaw is a time-of-check to time-of-use gap between two individually correct critical sections, visible only by reasoning about the whole function.

## Tests

`go test ./...` runs sequential tests of Deposit, Balance and the insufficient-funds path. Nothing is run concurrently.
