// SOPS support (age backend only) -- a second ciphertext format Decrypt
// understands, alongside Wharf's own plain-age whole-file format.
//
// Only a flat top-level map of scalar values is supported (a Wharf
// secrets file never nests) and only the age KMS backend is accepted;
// any other backend is a clear error. SOPS' own document-wide MAC is
// not verified on decrypt -- each value's AES-GCM tag already
// authenticates that value independently, which is enough given who can
// touch this file (the same admin who deploys the stack).
package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/goccy/go-yaml"
)

// looksLikeSOPS distinguishes a SOPS-encrypted YAML document from
// Wharf's own plain-age whole-file ciphertext by checking for a
// top-level "sops.age" list.
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

// looksArmored reports whether ciphertext is age's ASCII-armored form
// (age -a's output) rather than the raw binary form.
func looksArmored(ciphertext []byte) bool {
	return bytes.HasPrefix(ciphertext, []byte(armor.Header))
}

// unwrapArmor strips age's ASCII armor if present, otherwise passes
// ciphertext through unchanged.
func unwrapArmor(ciphertext []byte) io.Reader {
	if looksArmored(ciphertext) {
		return armor.NewReader(bytes.NewReader(ciphertext))
	}
	return bytes.NewReader(ciphertext)
}

// sopsEncPattern matches a SOPS-encrypted scalar value:
// ENC[AES256_GCM,data:<base64>,iv:<base64>,tag:<base64>,type:<word>]
var sopsEncPattern = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.*),iv:(.*),tag:(.*),type:(\w+)\]$`)

// decryptSOPS decrypts a SOPS document into the same "KEY=value\n"
// lines format Wharf's own plain-age whole-file secrets produce.
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
// whichever age recipient stanza (sops.age[].enc) our identity can
// open, trying each one in turn.
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
		// sops.age[].enc is ASCII-armored; unwrap before age.Decrypt.
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
	// SOPS uses a 32-byte GCM nonce, not Go's standard 12-byte one.
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

// ValidPublicKey reports whether s parses as a real age X25519 public key.
func ValidPublicKey(s string) bool {
	_, err := age.ParseX25519Recipient(s)
	return err == nil
}

// EncryptToRecipient encrypts plaintext to an arbitrary age public key --
// unlike Encrypt, which only ever encrypts to a stack this custodian
// already holds the key for, this takes any recipient with no lookup.
// The output is armored (age -a's ASCII form) rather than raw binary,
// since it's meant to be displayed and copied/downloaded as text.
func EncryptToRecipient(plaintext []byte, publicKey string) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	wc, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return nil, fmt.Errorf("start encryption: %w", err)
	}
	if _, err := wc.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("finalize encryption: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("finalize armor: %w", err)
	}
	return buf.Bytes(), nil
}

// EncryptSOPS shells out to the real `sops` CLI (bundled in the image,
// cf. Dockerfile) rather than re-implementing SOPS' write-side document
// format, so the result has a real MAC and is genuinely SOPS-compatible.
// Encryption only needs the recipient's public key, so no private key
// is ever exposed to the subprocess. --input-type/--output-type are
// required since plaintext arrives on stdin with no filename to infer a
// format from.
//
// publicKey is validated as a real age recipient before it becomes part
// of this subprocess's argv -- exec.Command never goes through a shell,
// so this isn't about shell injection, it just keeps a malformed value
// (e.g. one shaped like another sops flag) from reaching the subprocess
// at all.
func EncryptSOPS(plaintext []byte, publicKey string) ([]byte, error) {
	if !ValidPublicKey(publicKey) {
		return nil, fmt.Errorf("not a valid age public key")
	}
	cmd := exec.Command("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml", "--age", publicKey, "/dev/stdin")
	cmd.Stdin = bytes.NewReader(plaintext)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sops encrypt: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
