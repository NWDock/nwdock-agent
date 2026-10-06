package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

type sharedUser struct {
	Email  string `json:"email"`
	Secret string `json:"secret"`
}

type sharedDesired struct {
	Tag      string       `json:"tag"`
	Protocol string       `json:"protocol"`
	Method   string       `json:"method,omitempty"`
	Flow     string       `json:"flow,omitempty"`
	Users    []sharedUser `json:"users"`
}

// userStamp 把 method/flow 纳入对账值：任一变化都会触发该用户重加，而不是只比密码。
func userStamp(u sharedUser, item sharedDesired) string {
	return item.Protocol + "\x00" + item.Method + "\x00" + item.Flow + "\x00" + u.Secret
}

func isSS2022(method string) bool {
	return len(method) > 5 && method[:5] == "2022-"
}

func userJSON(item sharedDesired, email, secret string) map[string]any {
	user := map[string]any{"email": email, "level": 1}
	switch item.Protocol {
	case "vless":
		user["id"] = secret
		if item.Flow != "" {
			user["flow"] = item.Flow
		}
	default:
		user["password"] = secret
		if item.Protocol == "shadowsocks" {
			method := item.Method
			if method == "" {
				method = "aes-256-gcm"
			}
			user["method"] = method
		}
	}
	return user
}

func userFile(item sharedDesired, tag string, users []map[string]any) ([]byte, error) {
	settings := map[string]any{"clients": users}
	switch item.Protocol {
	case "vless":
		settings["decryption"] = "none"
	case "shadowsocks":
		method := item.Method
		if method == "" {
			method = "aes-256-gcm"
		}
		settings["method"] = method
		if isSS2022(method) {
			settings["password"] = ""
		}
	}
	return json.Marshal(map[string]any{
		"inbounds": []map[string]any{{
			"tag":      tag,
			"protocol": item.Protocol,
			"listen":   "127.0.0.1",
			"port":     1,
			"settings": settings,
		}},
	})
}

func loadAppliedUsers(dir string) map[string]map[string]string {
	raw, err := os.ReadFile(filepath.Join(dir, "applied-users.json"))
	if err != nil {
		return map[string]map[string]string{}
	}
	var applied map[string]map[string]string
	if err := json.Unmarshal(raw, &applied); err != nil {
		return map[string]map[string]string{}
	}
	if applied == nil {
		applied = map[string]map[string]string{}
	}
	return applied
}

func saveAppliedUsers(dir string, applied map[string]map[string]string) error {
	raw, err := json.Marshal(applied)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "applied-users.json"), raw, 0o600)
}

func clearAppliedUsers(dir string) {
	proc.appliedUsers = nil
	proc.usersLoaded = false
	_ = os.Remove(filepath.Join(dir, "applied-users.json"))
}

func appliedUsersLocked(dir string) map[string]map[string]string {
	if !proc.usersLoaded {
		proc.appliedUsers = loadAppliedUsers(dir)
		proc.usersLoaded = true
	}
	if proc.appliedUsers == nil {
		proc.appliedUsers = map[string]map[string]string{}
	}
	return proc.appliedUsers
}

func resetAppliedUsersLocked() {
	proc.appliedUsers = map[string]map[string]string{}
	proc.usersLoaded = true
}

func reconcileUsers(ctx context.Context, bin, api, dir string, shared []sharedDesired) error {
	proc.appliedUsers = appliedUsersLocked(dir)
	want := make(map[string]sharedDesired, len(shared))
	for _, item := range shared {
		if !safeTag(item.Tag) {
			return errors.New("tag")
		}
		switch item.Protocol {
		case "vless", "trojan", "shadowsocks":
		default:
			return fmt.Errorf("shared protocol %q", item.Protocol)
		}
		if _, dup := want[item.Tag]; dup {
			return fmt.Errorf("shared tag %s", item.Tag)
		}
		want[item.Tag] = item
	}
	for tag, emails := range proc.appliedUsers {
		if _, ok := want[tag]; ok {
			continue
		}
		list := make([]string, 0, len(emails))
		for email := range emails {
			list = append(list, email)
		}
		if err := removeUsers(ctx, bin, api, tag, list); err != nil {
			return err
		}
		delete(proc.appliedUsers, tag)
	}
	for tag, item := range want {
		have := proc.appliedUsers[tag]
		if item.Protocol == "shadowsocks" && isSS2022(item.Method) && have == nil && !hasUser(item.Users, "bootstrap") {
			if err := removeUsers(ctx, bin, api, tag, []string{"bootstrap"}); err != nil {
				fmt.Println("rmu bootstrap", tag, err)
			}
		}
		drop, add := diffUsers(have, item)
		if err := removeUsers(ctx, bin, api, tag, drop); err != nil {
			return err
		}
		var payload []map[string]any
		for _, user := range add {
			payload = append(payload, userJSON(item, user.Email, user.Secret))
		}
		if err := addUsers(ctx, bin, api, dir, item, tag, payload); err != nil {
			return err
		}
		next := make(map[string]string, len(item.Users))
		for _, user := range item.Users {
			next[user.Email] = userStamp(user, item)
		}
		proc.appliedUsers[tag] = next
	}
	return saveAppliedUsers(dir, proc.appliedUsers)
}

func diffUsers(have map[string]string, item sharedDesired) (drop []string, add []sharedUser) {
	for email := range have {
		if !hasUser(item.Users, email) {
			drop = append(drop, email)
		}
	}
	for _, user := range item.Users {
		if have[user.Email] != userStamp(user, item) {
			add = append(add, user)
		}
	}
	return drop, add
}

func hasUser(users []sharedUser, email string) bool {
	for _, user := range users {
		if user.Email == email {
			return true
		}
	}
	return false
}

var countRe = regexp.MustCompile(`(?:Added|Removed) (\d+) user\(s\) in total\.`)

func reportedCount(out []byte) (int, bool) {
	match := countRe.FindSubmatch(out)
	if match == nil {
		return 0, false
	}
	n, err := strconv.Atoi(string(match[1]))
	return n, err == nil
}

func removeUsers(ctx context.Context, bin, api, tag string, emails []string) error {
	if len(emails) == 0 {
		return nil
	}
	sort.Strings(emails)
	args := append([]string{"api", "rmu", "--server", api, "-tag", tag}, emails...)
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	if err != nil {
		return cmdFail("rmu "+tag, out, err)
	}
	if n, ok := reportedCount(out); !ok || n != len(emails) {
		return fmt.Errorf("rmu %s: %s", tag, safeOut(out))
	}
	fmt.Println("rmu", tag, len(emails))
	return nil
}

func addUsers(ctx context.Context, bin, api, dir string, item sharedDesired, tag string, users []map[string]any) error {
	if len(users) == 0 {
		return nil
	}
	raw, err := userFile(item, tag, users)
	if err != nil {
		return err
	}
	file := filepath.Join(dir, "users-"+tag+".json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, "api", "adu", "--server", api, file)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	_ = os.Remove(file)
	if err != nil {
		return cmdFail("adu "+tag, out, err)
	}
	if n, ok := reportedCount(out); !ok || n != len(users) {
		return fmt.Errorf("adu %s: %s", tag, safeOut(out))
	}
	fmt.Println("adu", tag, len(users))
	return nil
}
