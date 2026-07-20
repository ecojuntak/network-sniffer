//go:build !linux

package bpf

// Loader is a non-functional placeholder so the package builds on non-linux
// platforms (for local development and unit testing). All operations report
// ErrUnsupported.
type Loader struct{}

// New always fails on non-linux platforms.
func New() (*Loader, error) { return nil, ErrUnsupported }

// Read always fails on non-linux platforms.
func (l *Loader) Read() ([]byte, error) { return nil, ErrUnsupported }

// Close is a no-op on non-linux platforms.
func (l *Loader) Close() error { return nil }
