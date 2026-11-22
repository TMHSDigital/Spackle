package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"os"
)

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validAPIKey(given string) bool {
	want := os.Getenv("SERVICE_API_KEY")
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(given), []byte(want)) == 1
}

func etag(body []byte) string {
	sum := md5.Sum(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
