// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gitx

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseAddedLines(t *testing.T) {
	t.Parallel()
	diff := `diff --git a/a.go b/a.go
index 1..2 100644
--- a/a.go
+++ b/a.go
@@ -3,0 +4,2 @@ func x() {
+	// first
+	second()
@@ -10 +12 @@
-old
+new
diff --git a/gone.go b/gone.go
--- a/gone.go
+++ /dev/null
@@ -1 +0,0 @@
-bye
diff --git a/new.md b/new.md
new file mode 100644
--- /dev/null
+++ b/new.md
@@ -0,0 +1 @@
+hello
`
	want := []Line{
		{Path: "a.go", No: 4, Text: "\t// first"},
		{Path: "a.go", No: 5, Text: "\tsecond()"},
		{Path: "a.go", No: 12, Text: "new"},
		{Path: "new.md", No: 1, Text: "hello"},
	}
	if got := ParseAddedLines(diff); !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseAddedLines() = %#v, want %#v", got, want)
	}
}

// isolateGit clears the GIT_* variables git exports to hooks. Without this,
// running the tests from a pre-push hook makes `git init` in the temporary
// directory reinitialize the repository being pushed.
func isolateGit(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GIT_") {
			t.Setenv(name, "")
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func git(t *testing.T, args ...string) {
	t.Helper()
	if _, err := Run(context.Background(), args...); err != nil {
		t.Fatal(err)
	}
}

func TestAddedLinesIgnoresDeletionsAndRenames(t *testing.T) {
	dir := t.TempDir()
	isolateGit(t)
	t.Chdir(dir)
	t.Setenv("PRE_COMMIT_FROM_REF", "")
	t.Setenv("PRE_COMMIT_TO_REF", "")
	git(t, "init", "-q", "-b", "main")
	git(t, "config", "user.email", "test@example.com")
	git(t, "config", "user.name", "test")
	writeFile(t, "a.txt", "KEY-1\nkeep\ndrop\n")
	writeFile(t, "b.txt", "KEY-2\n")
	writeFile(t, "c.txt", "KEY-3\n")
	git(t, "add", ".")
	git(t, "commit", "-q", "-m", "init")

	writeFile(t, "a.txt", "KEY-1\nkeep\n")
	git(t, "mv", "b.txt", "renamed.txt")
	writeFile(t, "c.txt", "KEY-3\nadded\n")
	git(t, "add", "-A")

	tests := []struct {
		name  string
		files []string
		want  []Line
	}{
		{"deletion only", []string{"a.txt"}, nil},
		{"pure rename", []string{"renamed.txt"}, nil},
		{"added line", []string{"c.txt"}, []Line{{Path: "c.txt", No: 2, Text: "added"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddedLines(context.Background(), tt.files)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("AddedLines(%v) = %#v, want %#v", tt.files, got, tt.want)
			}
		})
	}
}

func TestAddedLinesReadsFilesOutsideTheDiff(t *testing.T) {
	dir := t.TempDir()
	isolateGit(t)
	t.Chdir(dir)
	t.Setenv("PRE_COMMIT_FROM_REF", "")
	t.Setenv("PRE_COMMIT_TO_REF", "")
	git(t, "init", "-q", "-b", "main")
	writeFile(t, "a.txt", "one\ntwo")
	got, err := AddedLines(context.Background(), []string{"a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Line{{Path: "a.txt", No: 1, Text: "one"}, {Path: "a.txt", No: 2, Text: "two"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AddedLines() = %#v, want %#v", got, want)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
