package envfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// Load sets variables from path when they are not already in the environment.
// A missing file is not an error. Existing variables are left unchanged.
func Load(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()
	values, err := parse(path, file)
	if err != nil {
		return err
	}
	for key, value := range values {
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return nil
}

// Read parses path and returns its assignments. It does not change the process
// environment. A missing file is an error.
func Read(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parse(path, file)
}

func parse(path string, r io.Reader) (map[string]string, error) {
	values := map[string]string{}
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if lineNo == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && (rest == "" || unicode.IsSpace(rune(rest[0]))) {
			line = strings.TrimSpace(rest)
		}
		key, raw, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validKey(key) {
			return nil, fmt.Errorf("%s:%d: invalid line", path, lineNo)
		}
		value, err := parseValue(raw)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid line", path, lineNo)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for i, r := range key {
		switch {
		case r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func parseValue(raw string) (string, error) {
	raw = strings.TrimLeftFunc(raw, unicode.IsSpace)
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '"', '\'':
		return parseQuoted(raw, raw[0])
	default:
		return strings.TrimSpace(raw), nil
	}
}

func parseQuoted(raw string, quote byte) (string, error) {
	var b strings.Builder
	for i := 1; i < len(raw); i++ {
		c := raw[i]
		if quote == '"' && c == '\\' {
			if i+1 >= len(raw) {
				return "", errors.New("invalid line")
			}
			i++
			switch raw[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case '\\', '"', '\'':
				b.WriteByte(raw[i])
			default:
				return "", errors.New("invalid line")
			}
			continue
		}
		if c == quote {
			rest := strings.TrimSpace(raw[i+1:])
			if rest == "" || strings.HasPrefix(rest, "#") {
				return b.String(), nil
			}
			return "", errors.New("invalid line")
		}
		b.WriteByte(c)
	}
	return "", errors.New("invalid line")
}

var legacyNoted sync.Map

// First returns primary when it is non-empty. Otherwise it returns the first
// non-empty alias and notes that alias on stderr once, without the value.
func First(primary string, aliases ...string) (string, string) {
	if v, ok := os.LookupEnv(primary); ok && v != "" {
		return v, ""
	}
	for _, name := range aliases {
		if v, ok := os.LookupEnv(name); ok && v != "" {
			noteLegacy(name)
			return v, name
		}
	}
	return "", ""
}

// Lookup returns primary when it is non-empty in values. Otherwise it returns
// the first non-empty alias and notes that alias on stderr once, without the value.
func Lookup(values map[string]string, primary string, aliases ...string) (string, string) {
	if v, ok := values[primary]; ok && v != "" {
		return v, ""
	}
	for _, name := range aliases {
		if v, ok := values[name]; ok && v != "" {
			noteLegacy(name)
			return v, name
		}
	}
	return "", ""
}

func noteLegacy(name string) {
	if _, loaded := legacyNoted.LoadOrStore(name, struct{}{}); loaded {
		return
	}
	fmt.Fprintf(os.Stderr, "legacy env: %s\n", name)
}

// LoadSide loads path when the file exists. A missing path falls back to fallback.
// usedFallback is true only when fallback was loaded. Missing both is not an error.
func LoadSide(path, fallback string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, Load(path)
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := os.Stat(fallback); err == nil {
		if err := Load(fallback); err != nil {
			return false, err
		}
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, err
	}
	return false, nil
}

// LoadProject loads name from the working directory, then its parent.
// If neither file exists, it does the same for fallback.
// dir is "." or ".." when a file was loaded, otherwise empty.
// legacy is true only when fallback was the file that loaded.
func LoadProject(name, fallback string) (dir string, legacy bool, err error) {
	if dir, ok, err := loadNamed(name); err != nil || ok {
		return dir, false, err
	}
	if dir, ok, err := loadNamed(fallback); err != nil || ok {
		return dir, true, err
	}
	return "", false, nil
}

func loadNamed(name string) (string, bool, error) {
	for _, dir := range []string{".", ".."} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", false, err
		}
		if info.IsDir() {
			continue
		}
		if err := Load(path); err != nil {
			return "", false, err
		}
		return dir, true, nil
	}
	return "", false, nil
}

// Against resolves a relative path against dir. Absolute paths, and an
// empty or "." dir, are returned unchanged.
func Against(dir, path string) string {
	if path == "" || filepath.IsAbs(path) || dir == "" || dir == "." {
		return path
	}
	abs, err := filepath.Abs(filepath.Join(dir, path))
	if err != nil {
		return path
	}
	return abs
}
