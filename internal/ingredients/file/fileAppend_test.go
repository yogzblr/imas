package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

func TestAppend(t *testing.T) {
	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "there-is-a-file-here")
	os.Create(existingFile)
	sampleDir := filepath.Join(tempDir, "there-is-a-dir-here")
	os.Mkdir(sampleDir, 0o755)
	file := filepath.Join(sampleDir, "there-is-a-file-here")
	os.Create(file)
	fileReadOnly := filepath.Join(tempDir, "there-is-a-read-only-file-here")
	_, err := os.Create(fileReadOnly)
	if err != nil {
		t.Fatalf("failed to create read-only file %s: %v", fileReadOnly, err)
	}
	err = os.Chmod(fileReadOnly, 0o444)
	if err != nil {
		t.Fatalf("failed to chmod read-only file %s: %v", fileReadOnly, err)
	}

	fileWithContent := filepath.Join(tempDir, "there-is-a-file-with-content-here")
	f, err := os.Create(fileWithContent)
	if err != nil {
		t.Fatalf("failed to create file with content %s: %v", fileWithContent, err)
	}
	_, err = f.WriteString("test")
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}
	f.Close()

	fileWithoutContent := filepath.Join(tempDir, "there-is-a-file-without-content-here")
	_, err = os.Create(fileWithoutContent)
	if err != nil {
		t.Fatalf("failed to create file without content %s: %v", fileWithoutContent, err)
	}

	// fakePath names a file that doesn't exist (a dangling symlink into a
	// missing directory), in a parent that does, and that can't be
	// created: os.Create follows the link and fails with ENOENT. That
	// holds for root too, unlike creating a file in "/", which CI
	// containers running tests as root simply succeed at.
	fakePath := filepath.Join(tempDir, "dangling-link")
	if err := os.Symlink(filepath.Join(tempDir, "missing-dir", "target"), fakePath); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	tests := []struct {
		name     string
		params   map[string]interface{}
		expected cook.Result
		error    error
		test     bool
	}{
		{
			name: "IncorrectFilename",
			params: map[string]interface{}{
				"name": 1,
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Notes:     []fmt.Stringer{},
			},
			error: ingredients.ErrMissingName,
		},
		{
			name: "AppendRoot",
			params: map[string]interface{}{
				"name": "/",
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Notes:     []fmt.Stringer{},
			},
			error: ErrModifyRoot,
		},
		{
			name: "AppendFileInvalidPermissions",
			params: map[string]interface{}{
				"name": fileReadOnly,
				"text": "test",
			},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Changed:   false,
				Notes:     []fmt.Stringer{cook.Snprintf("file %s does not contain all specified content", fileReadOnly)},
			},
			error: fmt.Errorf("failed to open %s for appending: open %s: permission denied", fileReadOnly, fileReadOnly),
		},
		{
			name:   "AppendFileWithContent",
			params: map[string]interface{}{"name": fileWithContent, "text": "test"},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   false,
				Notes:     []fmt.Stringer{},
			},
			error: nil,
		},
		{
			name:   "AppendFileWithoutContent",
			params: map[string]interface{}{"name": fileWithoutContent, "text": "test"},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   false,
				Notes:     []fmt.Stringer{cook.Snprintf("file %s does not contain all specified content", fileWithoutContent), cook.Snprintf("appended to %s", fileWithoutContent)},
			},
			error: nil,
		},
		{
			// The first run wrote the text, so a second finds it.
			name:   "AppendFileWithoutContentAgain",
			params: map[string]interface{}{"name": fileWithoutContent, "text": "test"},
			expected: cook.Result{
				Succeeded: true,
				Failed:    false,
				Changed:   false,
				Notes:     []fmt.Stringer{},
			},
			error: nil,
		},
		{
			name:   "AppendDirectory",
			params: map[string]interface{}{"name": fakePath},
			expected: cook.Result{
				Succeeded: false,
				Failed:    true,
				Changed:   false,
				Notes:     []fmt.Stringer{cook.Snprintf("failed to open %s", fakePath)},
			},
			// Only the stable prefix is asserted; the trailing OS error
			// text varies by platform.
			error: fmt.Errorf("failed to create %s: open %s:", fakePath, fakePath),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "AppendFileInvalidPermissions" && os.Geteuid() == 0 {
				// Root opens a 0o444 file for writing anyway, and there is
				// no portable way to make a readable regular file
				// unwritable for root. Unprivileged runs (CI) cover it.
				t.Skip("root bypasses file permissions")
			}
			f := File{
				id:     "",
				method: "",
				params: test.params,
			}
			result, err := f.append(context.TODO(), test.test)
			if err != nil || test.error != nil {
				if (err == nil && test.error != nil) || (err != nil && test.error == nil) {
					t.Errorf("expected error `%v`, got `%v`", test.error, err)
				} else if !strings.HasPrefix(err.Error(), test.error.Error()) {
					t.Errorf("expected error with prefix %v, got %v", test.error, err)
				}
			}
			compareResults(t, result, test.expected)
		})
	}
}

// TestAppendWritesTheText checks the file itself, not only the result:
// the append used to report "appended" while writing nothing, so every run
// appended again and the text never reached the file (UAT I.file.append).
func TestAppendWritesTheText(t *testing.T) {
	tests := []struct {
		name, initial string
		text          interface{}
		want          string
	}{
		{"one line", "line one\n", []interface{}{"imas uat x"}, "line one\nimas uat x\n"},
		{"string text", "line one\n", "imas uat x", "line one\nimas uat x\n"},
		{"list items are lines", "line one\n", []interface{}{"a", "b"}, "line one\na\nb\n"},
		{"only the missing lines", "b\nline one\n", []interface{}{"a", "b", "c"}, "b\nline one\na\nc\n"},
		{"last line without newline", "line one", []interface{}{"x"}, "line one\nx\n"},
		{"empty file", "", []interface{}{"x"}, "x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "f.txt")
			if err := os.WriteFile(name, []byte(tt.initial), 0o644); err != nil {
				t.Fatal(err)
			}
			f := File{method: "append", params: map[string]interface{}{"name": name, "text": tt.text}}

			res, err := f.append(context.Background(), true)
			if err != nil || !res.Changed {
				t.Fatalf("test mode: changed %v, err %v; want a pending change", res.Changed, err)
			}
			if got, _ := os.ReadFile(name); string(got) != tt.initial {
				t.Fatalf("test mode wrote the file: %q", got)
			}

			res, err = f.append(context.Background(), false)
			if err != nil || !res.Succeeded || !res.Changed {
				t.Fatalf("first run: %+v, err %v; want a change", res, err)
			}
			if got, _ := os.ReadFile(name); string(got) != tt.want {
				t.Fatalf("file holds %q, want %q", got, tt.want)
			}

			res, err = f.append(context.Background(), false)
			if err != nil || !res.Succeeded || res.Changed {
				t.Fatalf("second run: %+v, err %v; want no change", res, err)
			}
			if got, _ := os.ReadFile(name); string(got) != tt.want {
				t.Fatalf("second run changed the file to %q", got)
			}
		})
	}
}
