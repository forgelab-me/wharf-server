package keys

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

// Fixture generated with the real `sops` CLI (age backend), not written by
// hand -- this is the actual thing decryptSOPS has to be able to read,
// captured once rather than re-shelling out to sops on every test run.
// Keypair is throwaway, used only for this test.
const testAgePrivateKey = "AGE-SECRET-KEY-1LWFAQXAN3ACSA7G5CA8CQKUF4YS22FSKQAVQPEC4F4JA4NEN50AQTUGARV"

const testSOPSFixture = `DB_PASSWORD: ENC[AES256_GCM,data:JfhdfqoO,iv:N/8XSQh9L5eWhU5kfcYAKQM05CWGoP6ytN9vvSChZ1c=,tag:fK7Vhf1Ypf4XuQ5hvFYIUg==,type:str]
API_KEY: ENC[AES256_GCM,data:jCkPB83s,iv:IDTxV80ZHovFIO13EhXb0orktSBZ6Ddn60IcTNoHxgQ=,tag:4IuZXOOPZKCjycUxStwzFg==,type:str]
sops:
    age:
        - recipient: age1e89j0jf4ys63h9ql6wy5glc3clauu02php00qe46pksyye6fr4ksew60fy
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBxbzRGZi9IcVc5d1k3TTVX
            bzIvU1RUaU1jd3pMU0tyUkgxTjRpbWkyeG44Ck8vekZMOVVKa0hJd2FKWllINER6
            WmVQcDFRRjlmbkRwcktkcHJaQUZJRWcKLS0tIE9SejUvOVc2QzFFdGFhdi9nWnVO
            SHhpTldILzFaNGFwb2hTSis1WFFzRE0KFqmQT3aUFpx4lAXw6RmDt7JKEE2gZ4EP
            Yli3o1iBIJqvU6WuAjnuzZ1y+csbK6bffQRoqoOf36qYUh0u6Y2WxQ==
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-09-28T14:01:16Z"
    mac: ENC[AES256_GCM,data:1Z2Q/t6DyNqCjLCIBkLPqdARIt5y+sbWNcsYZvzmQPc7DgGbjDZYQ4A4YyNNOvz91oMUHfjFA0e9lU1XKi8zkhvwY4nR1TcxWZe01fF8mFERAWNGXoCRNyS6f23XkWEwFjsCbx+/2XPe6Xt2FuES9GmBjWelOWxA6oHMoLFuVso=,iv:HXTpxShUegL+HQzmS9osoLXILXibbLW2ALBnLJk3AZE=,tag:A1q5u8j5LA/X385Ptr01KQ==,type:str]
    unencrypted_suffix: _unencrypted
    version: 3.12.2
`

func TestLooksLikeSOPS(t *testing.T) {
	if !looksLikeSOPS([]byte(testSOPSFixture)) {
		t.Fatal("real sops output not detected as SOPS")
	}
	if looksLikeSOPS([]byte("just a plain env line\nFOO=bar\n")) {
		t.Fatal("plain text falsely detected as SOPS")
	}
}

func TestDecryptSOPSAgainstRealSOPSOutput(t *testing.T) {
	identity, err := age.ParseX25519Identity(testAgePrivateKey)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}

	out, err := decryptSOPS([]byte(testSOPSFixture), identity)
	if err != nil {
		t.Fatalf("decryptSOPS: %v", err)
	}

	want := "API_KEY=abc123\nDB_PASSWORD=s3cr3t\n" // sorted by key, cf. decryptSOPS
	if string(out) != want {
		t.Errorf("decryptSOPS = %q, want %q", out, want)
	}
}

func TestDecryptSOPSWrongIdentityFailsClosed(t *testing.T) {
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if _, err := decryptSOPS([]byte(testSOPSFixture), other); err == nil {
		t.Fatal("expected an error decrypting with the wrong identity, got nil")
	}
}

// EncryptToRecipient's whole reason to exist over a bare age.Encrypt is
// armoring the result for safe display/copy as text (cf. its own
// comment) -- this round-trips that armored output back through exactly
// what Custodian.Decrypt does (unwrapArmor then age.Decrypt), the real
// path a Git stack's secrets.enc.yaml goes through, to prove that
// choice didn't break decrypting it back.
func TestEncryptToRecipientRoundTripsThroughUnwrapArmor(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	ciphertext, err := EncryptToRecipient([]byte("DB_PASSWORD=s3cr3t"), identity.Recipient().String())
	if err != nil {
		t.Fatalf("EncryptToRecipient: %v", err)
	}
	if !looksArmored(ciphertext) {
		t.Fatal("EncryptToRecipient output is not armored")
	}
	if !utf8Printable(ciphertext) {
		t.Fatal("armored output should be plain printable text, safe to copy/display")
	}

	r, err := age.Decrypt(unwrapArmor(ciphertext), identity)
	if err != nil {
		t.Fatalf("decrypt armored output: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read plaintext: %v", err)
	}
	if buf.String() != "DB_PASSWORD=s3cr3t" {
		t.Errorf("round-tripped plaintext = %q, want %q", buf.String(), "DB_PASSWORD=s3cr3t")
	}
}

// unwrapArmor must be a no-op passthrough for raw (non-armored)
// ciphertext -- Custodian.Encrypt's own output (never armored) has to
// keep decrypting exactly as it always did.
func TestUnwrapArmorPassesThroughRawCiphertext(t *testing.T) {
	raw := []byte("age-encryption.org/v1\nnot a real file, just needs the right prefix\n")
	r := unwrapArmor(raw)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("unwrapArmor changed non-armored input: got %q, want %q", got, raw)
	}
}

func utf8Printable(b []byte) bool {
	return strings.TrimFunc(string(b), func(r rune) bool {
		return r == '\n' || (r >= 0x20 && r < 0x7f)
	}) == ""
}

func TestValidPublicKey(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if !ValidPublicKey(id.Recipient().String()) {
		t.Fatal("a real recipient string should be valid")
	}
	for _, bad := range []string{"", "--decrypt", "-o", "not-a-key", "age1tooshort"} {
		if ValidPublicKey(bad) {
			t.Errorf("ValidPublicKey(%q) = true, want false", bad)
		}
	}
}

// EncryptSOPS must reject anything that isn't already a well-formed
// age1... key *before* it ever becomes part of the sops subprocess's
// argv -- cf. EncryptSOPS's own comment on why this matters more than
// the usual "exec.Command never goes through a shell" answer alone.
// Every case here would otherwise become the literal value handed to
// sops' own "--age" flag.
func TestEncryptSOPSRejectsMalformedPublicKeyBeforeSubprocess(t *testing.T) {
	for _, pk := range []string{"", "--decrypt", "-o", "/tmp/pwned", "not-a-key"} {
		if _, err := EncryptSOPS([]byte("FOO: bar\n"), pk); err == nil {
			t.Errorf("EncryptSOPS(publicKey=%q) should have been rejected, got nil error", pk)
		}
	}
}
