package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var errEmptyName = errors.New("empty document name")

type DocStore struct {
	base string
}

func NewDocStore(base string) *DocStore {
	return &DocStore{base: base}
}

func contentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".json":
		return "application/json"
	case ".pdf":
		return "application/pdf"
	}
	return "application/octet-stream"
}

func (s *DocStore) resolve(name string) string {
	return filepath.Join(s.base, name)
}

func (s *DocStore) Load(name string) ([]byte, error) {
	if name == "" {
		return nil, errEmptyName
	}
	return os.ReadFile(s.resolve(name))
}
