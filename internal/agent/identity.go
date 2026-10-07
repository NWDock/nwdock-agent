package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// identity 是节点的长期身份：Ed25519 密钥对，指纹 = SHA256(公钥)（keypin.Fingerprint）。
// 替代已废弃的 agent.crt/agent.key 证书体系；轮换身份 = 删文件 + 新安装令牌重登记。
type identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// loadOrCreateIdentity 读取 dir/agent-identity.key（Ed25519 raw 64 字节，0600）；
// 不存在则本地生成并落盘。已是令牌登记过的节点复用该密钥直连面板。
func loadOrCreateIdentity(dir string) (*identity, error) {
	path := filepath.Join(dir, "agent-identity.key")
	raw, err := os.ReadFile(path)
	if err == nil {
		// 原始字节流，不能 trim：末尾可能恰好是空白位（概率约 2%），trim 会把 64 字节啃成 63。
		switch len(raw) {
		case ed25519.SeedSize:
			return identityFromSeed(raw), nil
		case ed25519.PrivateKeySize:
			return identityFromSeed(raw[:ed25519.SeedSize]), nil
		default:
			return nil, fmt.Errorf("agent-identity.key: want %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return &identity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func identityFromSeed(seed []byte) *identity {
	priv := ed25519.NewKeyFromSeed(seed)
	return &identity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}
