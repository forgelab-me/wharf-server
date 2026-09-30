package secrets

import (
	"context"
	"fmt"
)

const (
	sopsScheme = "sops"
	// EncFileName is the only file the sops provider reads.
	EncFileName = "secrets.enc.yaml"
)

type sopsProvider struct{}

// SOPSProvider serves ref+sops://secrets.enc.yaml#/KEY from the stack's own
// encrypted file. It needs no connection.
func SOPSProvider() Provider { return sopsProvider{} }

func (sopsProvider) Scheme() string { return sopsScheme }

func (sopsProvider) Resolve(_ context.Context, job *Job, ref Ref) (string, error) {
	if ref.Path != EncFileName {
		return "", fmt.Errorf("only %s can be referenced", EncFileName)
	}
	values, err := job.encFileValues()
	if err != nil {
		return "", err
	}
	v, ok := values[ref.Field]
	if !ok {
		return "", fmt.Errorf("key %q not found in %s", ref.Field, EncFileName)
	}
	return v, nil
}
