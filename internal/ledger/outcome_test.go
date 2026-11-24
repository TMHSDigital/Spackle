package ledger

import "testing"

// The outcome, verdict and stage words are stored in ledgers and read by
// reports, exit codes and other tools. A renamed constant must not change
// the word.
func TestStoredWordsDoNotChange(t *testing.T) {
	for got, want := range map[string]string{
		OutcomeCompleted: "completed", OutcomeBudgetExhausted: "budget-exhausted",
		OutcomeInterrupted: "interrupted", OutcomeFailed: "failed", OutcomeIncomplete: "incomplete",
		VerdictConfirmed: "confirmed", VerdictDismissed: "dismissed",
		VerdictDemonstrated: "demonstrated", VerdictNotReproduced: "not-reproduced",
		VerdictFixed: "fixed", VerdictFixUnverified: "fix-unverified", VerdictFixRejected: "fix-rejected",
		VerdictStillReproduces: "still-reproduces", VerdictNoLongerReproduces: "no-longer-reproduces",
		VerdictInconclusive: "inconclusive",
	} {
		if got != want {
			t.Errorf("stored word %q, want %q", got, want)
		}
	}
	if len(Outcomes()) != 5 {
		t.Errorf("Outcomes() = %v, want the five outcomes", Outcomes())
	}
}
