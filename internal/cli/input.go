package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
)

// maxValue bounds a secret value. A value must fit in one protocol message
// (1 MiB) even after base64 encoding.
const maxValue = 512 << 10

// readValue reads a secret value, in order of preference: the file given by
// fromFile (byte for byte), stdin when it isn't a terminal, or a hidden
// prompt when stdin and stderr are both terminals. From stdin or a prompt,
// one trailing line break is dropped, so `echo token | foca add` stores
// "token". The caller zeroes the result.
func readValue(e *Env, what, fromFile string) ([]byte, error) {
	var b []byte
	var err error
	switch {
	case fromFile != "":
		b, err = readFileLimited(fromFile)
	case !e.StdinTTY:
		b, err = readLimited(e.Stdin)
		b = trimLineBreak(b)
	case e.StderrTTY:
		fmt.Fprintf(e.Stderr, "%s (input hidden): ", what)
		b, err = e.ReadPassword()
		fmt.Fprintln(e.Stderr)
		b = trimLineBreak(b)
	default:
		return nil, errors.New("no value given: pipe it on stdin or use --from-file (a hidden prompt needs stdin and stderr to be a terminal)")
	}
	if err != nil {
		zero(b)
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("the value is empty")
	}
	return b, nil
}

// readRecoveryKey reads a vault's recovery key: from a hidden prompt, or
// from the first line of stdin when stdin isn't a terminal. The caller
// zeroes the result.
func readRecoveryKey(e *Env, vault string) ([]byte, error) {
	what := "recovery key for vault " + vault
	typed, err := readLine(e, what)
	if err != nil {
		return nil, err
	}
	defer zero(typed)
	key, err := vaultfile.ParseRecoveryKey(typed)
	if err != nil {
		return nil, fmt.Errorf("the %s: %w", what, err)
	}
	return key, nil
}

// readLine reads one hidden line: from a prompt, or from the first line of
// stdin when stdin isn't a terminal.
func readLine(e *Env, what string) ([]byte, error) {
	if !e.StdinTTY {
		b, err := readLimited(e.Stdin)
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			zero(b[i:])
			b = b[:i]
		}
		b = bytes.TrimSuffix(b, []byte("\r"))
		if err != nil || len(b) == 0 {
			zero(b)
			return nil, fmt.Errorf("no %s on stdin", what)
		}
		return b, nil
	}
	if !e.StderrTTY {
		return nil, fmt.Errorf("no %s given: pipe it on stdin (a hidden prompt needs stdin and stderr to be a terminal)", what)
	}
	fmt.Fprintf(e.Stderr, "%s (input hidden): ", what)
	b, err := e.ReadPassword()
	fmt.Fprintln(e.Stderr)
	if err != nil {
		zero(b)
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("the %s is empty", what)
	}
	return b, nil
}

func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxValue+1))
	if err != nil {
		zero(b)
		return nil, err
	}
	if len(b) > maxValue {
		zero(b)
		return nil, fmt.Errorf("the value is larger than %d bytes", maxValue)
	}
	return b, nil
}

func readFileLimited(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f)
}

func trimLineBreak(b []byte) []byte {
	switch {
	case bytes.HasSuffix(b, []byte("\r\n")):
		return b[:len(b)-2]
	case bytes.HasSuffix(b, []byte("\n")):
		return b[:len(b)-1]
	}
	return b
}

// checkOutput vets path for a secret before anyone is asked to approve the
// read: an existing file must be a regular file of ours, not a symlink, a
// directory or a device such as a terminal; a new one needs an existing
// directory.
func checkOutput(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		di, err := os.Stat(filepath.Dir(path))
		if err != nil {
			return err
		}
		if !di.IsDir() {
			return fmt.Errorf("%s is not a directory", filepath.Dir(path))
		}
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a regular file of the current user; refusing to write a secret to it", path)
	}
	return nil
}

// writeOutput replaces path with a new 0600 file holding b, through a
// temporary file and a rename. The old file is never written to, so a hard
// link to it, or a reader that already has it open, never sees the secret.
func writeOutput(path string, b []byte) error {
	if err := checkOutput(path); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, b, 0o600)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
