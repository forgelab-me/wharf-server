package secrets

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CallTimeout bounds a single provider call.
const CallTimeout = 10 * time.Second

// Provider resolves references for one scheme.
type Provider interface {
	Scheme() string
	Resolve(ctx context.Context, job *Job, ref Ref) (string, error)
}

// Job is the per-deployment input shared by every provider.
type Job struct {
	StackID string
	// EncFile is the repository's secrets.enc.yaml ciphertext, empty when absent.
	EncFile []byte
	// DecryptEnc decrypts EncFile with the stack's own key.
	DecryptEnc func(stackID string, ciphertext []byte) (map[string]string, error)
	// Binding returns the stack's connection for a scheme, or a NoBindingError.
	Binding func(scheme string) (*Effective, error)

	encValues map[string]string
	encErr    error
	encLoaded bool

	effective map[string]effectiveResult
	memo      map[string]memoResult
}

type effectiveResult struct {
	eff *Effective
	err error
}

type memoResult struct {
	v   any
	err error
}

// Effective returns the stack's connection for a scheme, looked up once.
func (j *Job) Effective(scheme string) (*Effective, error) {
	if r, ok := j.effective[scheme]; ok {
		return r.eff, r.err
	}
	var r effectiveResult
	if j.Binding == nil {
		r.err = &NoBindingError{Scheme: scheme}
	} else {
		r.eff, r.err = j.Binding(scheme)
	}
	if j.effective == nil {
		j.effective = map[string]effectiveResult{}
	}
	j.effective[scheme] = r
	return r.eff, r.err
}

// Memo runs fn once per key for the lifetime of the job.
func (j *Job) Memo(key string, fn func() (any, error)) (any, error) {
	if r, ok := j.memo[key]; ok {
		return r.v, r.err
	}
	v, err := fn()
	if j.memo == nil {
		j.memo = map[string]memoResult{}
	}
	j.memo[key] = memoResult{v, err}
	return v, err
}

// encFileValues decrypts EncFile once per job.
func (j *Job) encFileValues() (map[string]string, error) {
	if !j.encLoaded {
		j.encLoaded = true
		switch {
		case len(j.EncFile) == 0:
			j.encErr = fmt.Errorf("%s was not found next to the compose file", EncFileName)
		case j.DecryptEnc == nil:
			j.encErr = fmt.Errorf("%s cannot be decrypted here", EncFileName)
		default:
			j.encValues, j.encErr = j.DecryptEnc(j.StackID, j.EncFile)
		}
	}
	return j.encValues, j.encErr
}

// Result is the environment to deploy with, plus non-fatal notices.
type Result struct {
	Env   map[string]string
	Notes []string
	// Sources lists, per connection-based scheme used, where its credentials came from.
	Sources []string
}

// Failure is one reference that could not be resolved.
type Failure struct {
	Key string
	Ref Ref
	Err error
}

// ResolveError lists every failed reference.
type ResolveError struct {
	Failures []Failure
}

func (e *ResolveError) Error() string {
	lines := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		lines[i] = fmt.Sprintf("%s (%s://): %v", f.Key, f.Ref.Scheme, f.Err)
	}
	return fmt.Sprintf("%d reference(s) could not be resolved:\n  %s", len(e.Failures), strings.Join(lines, "\n  "))
}

// Resolver routes each reference to the provider for its scheme.
type Resolver struct {
	providers map[string]Provider
}

func NewResolver(providers ...Provider) *Resolver {
	r := &Resolver{providers: map[string]Provider{}}
	for _, p := range providers {
		r.providers[p.Scheme()] = p
	}
	return r
}

// Connector returns the connection-based provider for a scheme.
func (r *Resolver) Connector(scheme string) (Connector, bool) {
	c, ok := r.providers[scheme].(Connector)
	return c, ok
}

// Connectors lists every connection-based provider, ordered by scheme.
func (r *Resolver) Connectors() []Connector {
	var out []Connector
	for _, p := range r.providers {
		if c, ok := p.(Connector); ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scheme() < out[j].Scheme() })
	return out
}

// Resolve resolves every entry. Any failure fails the whole job (no
// fallback to another source), and all failures are reported together.
func (r *Resolver) Resolve(ctx context.Context, job *Job, entries []Entry) (Result, error) {
	res := Result{Env: make(map[string]string, len(entries))}
	var failures []Failure

	for _, e := range entries {
		p, ok := r.providers[e.Ref.Scheme]
		if !ok {
			failures = append(failures, Failure{e.Key, e.Ref, fmt.Errorf("no provider for %q is available", e.Ref.Scheme)})
			continue
		}
		if _, needsConnection := p.(Connector); needsConnection {
			eff, err := job.Effective(e.Ref.Scheme)
			if err != nil {
				failures = append(failures, Failure{e.Key, e.Ref, err})
				continue
			}
			if !PathAllowed(eff.Prefixes, e.Ref.Path) {
				failures = append(failures, Failure{e.Key, e.Ref, fmt.Errorf("path %q is outside the prefixes allowed for this stack (%s)", e.Ref.Path, strings.Join(eff.Prefixes, ", "))})
				continue
			}
		}
		callCtx, cancel := context.WithTimeout(ctx, CallTimeout)
		v, err := p.Resolve(callCtx, job, e.Ref)
		cancel()
		if err != nil {
			failures = append(failures, Failure{e.Key, e.Ref, err})
			continue
		}
		res.Env[e.Key] = v
	}
	if len(failures) > 0 {
		return Result{}, &ResolveError{Failures: failures}
	}

	res.Notes = unreferencedEncKeys(job, entries)
	res.Sources = usedSources(job, entries)
	return res, nil
}

// usedSources names, once per scheme, the connection each reference went through.
func usedSources(job *Job, entries []Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if seen[e.Ref.Scheme] {
			continue
		}
		seen[e.Ref.Scheme] = true
		if eff, err := job.Effective(e.Ref.Scheme); err == nil && eff != nil {
			out = append(out, e.Ref.Scheme+": "+eff.Source)
		}
	}
	sort.Strings(out)
	return out
}

// unreferencedEncKeys names the keys of secrets.enc.yaml that no
// ref+sops:// entry picks up. A file that cannot be decrypted is only an
// error when a reference actually needs it.
func unreferencedEncKeys(job *Job, entries []Entry) []string {
	if len(job.EncFile) == 0 {
		return nil
	}
	values, err := job.encFileValues()
	if err != nil {
		return nil
	}
	used := map[string]bool{}
	for _, e := range entries {
		if e.Ref.Scheme == sopsScheme {
			used[e.Ref.Field] = true
		}
	}
	var missing []string
	for k := range values {
		if !used[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return []string{fmt.Sprintf("%s keys not referenced (ignored): %s", EncFileName, strings.Join(missing, ", "))}
}
