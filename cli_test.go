package main

import "testing"

func TestShouldUseHashCompatibilityMode(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no args", args: nil, want: true},
		{name: "hash command", args: []string{"hash"}, want: false},
		{name: "snapshot command", args: []string{"snapshot"}, want: false},
		{name: "help command", args: []string{"help"}, want: false},
		{name: "hash flags shorthand", args: []string{"-algos", "blake3"}, want: true},
		{name: "path shorthand", args: []string{"./data"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUseHashCompatibilityMode(tt.args)
			if got != tt.want {
				t.Fatalf("shouldUseHashCompatibilityMode(%v)=%v want=%v", tt.args, got, tt.want)
			}
		})
	}
}

func TestRootCommandContainsCoreTools(t *testing.T) {
	root := newRootCommand()
	if _, _, err := root.Find([]string{"hash"}); err != nil {
		t.Fatalf("expected hash command to be registered: %v", err)
	}
	if _, _, err := root.Find([]string{"snapshot"}); err != nil {
		t.Fatalf("expected snapshot command to be registered: %v", err)
	}
}
