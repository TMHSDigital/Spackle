package walk

import "sync"

// MaxHeldText is the most text, in bytes, that a Texts holds at one time.
const MaxHeldText = 64 << 20

// Texts hands the text of files from one stage of a scan to the next, so a
// file the mapper read is not read again by the seeders. A text is held
// until it is taken, and at most MaxHeldText bytes are held: past that a
// text is not kept, and the next stage reads that file itself. Memory use
// is therefore bounded however large the target is.
//
// A nil *Texts holds nothing, so a stage can be run without one. A Texts is
// safe for concurrent use.
type Texts struct {
	mu   sync.Mutex
	held map[string]string
	size int
}

// NewTexts returns an empty Texts.
func NewTexts() *Texts { return &Texts{held: map[string]string{}} }

// Put keeps the text of the file at abs, as ReadText returned it, when
// there is room for it.
func (t *Texts) Put(abs, text string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.held[abs]; ok || t.size+len(text) > MaxHeldText {
		return
	}
	t.held[abs] = text
	t.size += len(text)
}

// Get returns the text kept for abs and keeps it.
func (t *Texts) Get(abs string) (text string, ok bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	text, ok = t.held[abs]
	return text, ok
}

// Take returns the text kept for abs and forgets it. ok is false when none
// was kept.
func (t *Texts) Take(abs string) (text string, ok bool) {
	if t == nil {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if text, ok = t.held[abs]; ok {
		delete(t.held, abs)
		t.size -= len(text)
	}
	return text, ok
}
