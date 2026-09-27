package log

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
)

// RotatingFile is an io.WriteCloser that appends to a file and, before a
// write would take it past maxSize bytes, rotates it (see RotateFile) and
// starts a new one. It's the log file of a process with no log collector
// of its own, such as the sprout under the Windows SCM.
type RotatingFile struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	keep    int
	f       *os.File
	size    int64
	closed  bool
}

// OpenRotatingFile opens (creating it, mode 0600) path for appending,
// keeping up to keep rotated files of about maxSize bytes each.
func OpenRotatingFile(path string, maxSize int64, keep int) (*RotatingFile, error) {
	if maxSize <= 0 || keep < 1 {
		return nil, fmt.Errorf("log: rotating file %s: maxSize %d and keep %d must be positive", path, maxSize, keep)
	}
	r := &RotatingFile{path: path, maxSize: maxSize, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, info.Size()
	return nil
}

// Write appends p, rotating first if the file is not empty and p would
// take it past maxSize. A single write is never split across files.
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.f == nil {
		// An earlier reopen failed; try again rather than drop every
		// later entry.
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate closes the file, rotates it and opens a new one. If the rename
// fails (on Windows, another process can hold the file open without
// sharing delete), it reopens and keeps appending to the same file, and
// waits another maxSize bytes before trying again. It returns an error
// only when no file could be reopened.
func (r *RotatingFile) rotate() error {
	r.f.Close()
	r.f = nil
	renameErr := RotateFile(r.path, r.keep)
	if err := r.open(); err != nil {
		return err
	}
	if renameErr != nil {
		r.size = 0
	}
	return nil
}

// Close closes the file; later writes fail with os.ErrClosed.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// RotateFile renames path to path.1, after shifting path.1 … path.<keep-1>
// up by one and removing path.<keep>. Missing files are skipped. It returns
// the first other error, after attempting every step.
func RotateFile(path string, keep int) error {
	var errs []error
	note := func(err error) {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	note(os.Remove(fmt.Sprintf("%s.%d", path, keep)))
	for i := keep - 1; i >= 1; i-- {
		note(os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1)))
	}
	note(os.Rename(path, path+".1"))
	return errors.Join(errs...)
}
