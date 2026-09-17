// SOPS decryption (age backend only) — a second ciphertext format
// Decrypt understands, alongside Wharf's own plain-age whole-file
// format. Added because a real user's existing secrets.enc.yaml files
// are already SOPS output (age as SOPS' KMS backend) from an established
// workflow used elsewhere in their infrastructure, not something they
// were willing to give up just for Wharf.
//
// Scope, stated plainly rather than silently narrowed: only a flat
// top-level map of scalar values is supported — a Wharf secrets file
// has no reason to nest (env vars aren't nested), so this doesn't try
// to replicate SOPS' full tree-walk path/AAD convention for maps and
// lists at arbitrary depth. Only the age KMS backend is accepted — any
// other backend (AWS/GCP/Azure KMS, PGP, HashiCorp Vault) is a clear
// error, not a silent skip. SOPS' own MAC (sops.mac, a second layer of
// tamper-detection over the whole document) is deliberately not
// verified: every value's own AES-GCM tag already authenticates that
// exact value independently — a tampered or truncated ENC[...] fails
// closed on its own, which covers the realistic threat model here (the
// same admin who deploys the stack controls this file). Replicating
// SOPS' exact MAC string-concatenation algorithm on top of that buys
// little for meaningfully more surface to get subtly wrong.
package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/goccy/go-yaml"
)

// looksLikeSOPS distinguishes a SOPS-encrypted YAML document from
// Wharf's own plain-age whole-file ciphertext via a real YAML parse
// (not a string search) for the one shape that matters: a top-level
// "sops.age" list. Raw age ciphertext is binary and essentially never
// round-trips through a YAML parser into exactly this shape, so this
// has no meaningful false-positive risk in practice.
func looksLikeSOPS(ciphertext []byte) bool {
	var probe struct {
		Sops struct {
			Age []struct {
				Enc string `yaml:"enc"`
			} `yaml:"age"`
		} `yaml:"sops"`
	}
	if err := yaml.Unmarshal(ciphertext, &probe); err != nil {
		return false
	}
	return len(probe.Sops.Age) > 0
}

// sopsEncPattern matches a SOPS-encrypted scalar value:
// ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<word>]
var sopsEncPattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.*),iv:(.*),tag:(.*),type:(\w+)\]$`)

// decryptSOPS decrypts a SOPS document into the same "KEY=value\n"
// lines format Wharf's own plain-age whole-file secrets already
// produce, so every downstream caller (parseEnvLines, on both the
// controller's local-stack path and the agent's Git-stack path) needs
// no changes at all — the format dispatch lives entirely inside
// Decrypt, below.
func decryptSOPS(ciphertext []byte, identity *age.X25519Identity) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(ciphertext, &doc); err != nil {
		return nil, fmt.Errorf("parse sops yaml: %w", err)
	}

	sopsMeta, ok := doc["sops"].(map[string]any)
	if !ok {
		return nil, errors.New("sops: missing top-level \"sops\" metadata")
	}
	delete(doc, "sops")

	dataKey, err := sopsDataKey(sopsMeta, identity)
	if err != nil {
		return nil, fmt.Errorf("sops: %w", err)
	}

	names := make([]string, 0, len(doc))
	for k := range doc {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic output order only -- env lines have no inherent order

	var out bytes.Buffer
	for _, k := range names {
		s, ok := doc[k].(string)
		if !ok {
			return nil, fmt.Errorf("sops: key %q is not a flat scalar value (nested maps/lists aren't supported)", k)
		}
		plain, err := sopsDecryptValue(s, dataKey, k+":")
		if err != nil {
			return nil, fmt.Errorf("sops: decrypt key %q: %w", k, err)
		}
		fmt.Fprintf(&out, "%s=%s\n", k, plain)
	}
	return out.Bytes(), nil
}

// sopsDataKey decrypts SOPS' own randomly-generated data key from
// whichever age recipient stanza (sops.age[].enc, itself an ordinary
// ASCII-armored age file) our identity can open — the same age package
// Wharf already uses for its whole-file format, just applied to this
// nested blob instead of the outer document. A stanza meant for a
// different recipient simply fails to open; every stanza is tried
// before giving up, matching sops' own multi-recipient tolerance.
func sopsDataKey(sopsMeta map[string]any, identity *age.X25519Identity) ([]byte, error) {
	ageStanzas, ok := sopsMeta["age"].([]any)
	if !ok || len(ageStanzas) == 0 {
		return nil, errors.New("no age recipients in sops metadata (only the age KMS backend is supported)")
	}
	var lastErr error
	for _, raw := range ageStanzas {
		stanza, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		enc, _ := stanza["enc"].(string)
		if enc == "" {
			continue
		}
		// sops.age[].enc is ASCII-armored (-----BEGIN AGE ENCRYPTED
		// FILE-----...), unlike Wharf's own whole-file format which age
		// itself always writes unarmored -- unwrap it before handing the
		// raw age.Decrypt stream reader its expected binary framing.
		r, err := age.Decrypt(armor.NewReader(strings.NewReader(enc)), identity)
		if err != nil {
			lastErr = err
			continue
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(r); err != nil {
			lastErr = err
			continue
		}
		return buf.Bytes(), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable age recipient stanza")
	}
	return nil, fmt.Errorf("decrypt data key: %w", lastErr)
}

// sopsDecryptValue decrypts one ENC[...] scalar. additionalData is
// SOPS' own tree-path AAD convention ("<key>:" for a top-level scalar)
// — get it wrong and AES-GCM's tag check fails closed, it never
// silently returns the wrong plaintext.
func sopsDecryptValue(enc string, dataKey []byte, additionalData string) (string, error) {
	m := sopsEncPattern.FindStringSubmatch(enc)
	if m == nil {
		return "", errors.New("value is not an ENC[...] sops value")
	}
	data, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return "", fmt.Errorf("decode data: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		return "", fmt.Errorf("decode iv: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil {
		return "", fmt.Errorf("decode tag: %w", err)
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", fmt.Errorf("init aes cipher: %w", err)
	}
	// SOPS uses a 32-byte GCM nonce, not the standard 12-byte one Go's
	// cipher.NewGCM assumes -- confirmed against real sops CLI output
	// (its own "iv" field is consistently 32 bytes), not guessed from
	// the spec alone. NewGCMWithNonceSize accepts whatever length the
	// ciphertext actually used.
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return "", fmt.Errorf("init gcm: %w", err)
	}
	plaintext, err := aead.Open(nil, iv, append(data, tag...), []byte(additionalData))
	if err != nil {
		return "", fmt.Errorf("gcm open (wrong key or tampered value): %w", err)
	}
	return string(plaintext), nil
}
