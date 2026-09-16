//go:build !windows

package keystore

// Linux: a TPM-backed key needs a TSS stack this pure-Go build does not carry
// (unverified stub). macOS: Keychain and Secure Enclave need CGO. Both use a
// file key owned by the dedicated broker service identity instead.
func platformDefault(opts Options) (Store, error) {
	if opts.PreferTPM {
		return nil, ErrRequiresCGO
	}
	if opts.Dir == "" {
		return nil, ErrUnavailable
	}
	return &FileStore{Dir: opts.Dir, Development: opts.Development}, nil
}
