package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ScriptEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"` // lowercase hex
}

type Manifest struct {
	Scripts []ScriptEntry `json:"scripts"`
	index   map[string]ScriptEntry
}

func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	m.index = make(map[string]ScriptEntry, len(m.Scripts))
	for _, s := range m.Scripts {
		abs := s.Path
		if !filepath.IsAbs(abs) {
			abs = filepath.Clean(filepath.Join(filepath.Dir(path), "..", s.Path))
		}
		s.Path = abs
		m.index[s.Name] = s
	}
	return &m, nil
}

func (m *Manifest) Lookup(name string) (ScriptEntry, bool) {
	v, ok := m.index[name]
	return v, ok
}

func SHA256File(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
