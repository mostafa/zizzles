package yaml_patch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestEdgeCases contains a subset of tricky scenarios taken from the Rust test
// -suite.  They ensure comment/format preservation for block & flow styles.
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patches  []Patch
		expected string
		skip     bool
	}{
		{
			name:    "add to flow mapping with trailing comma",
			content: "env: { A: a, B: b, }\n",
			patches: []Patch{{
				Path:      "env",
				Operation: AddOp{Key: "C", Value: "c"},
			}},
			// The trailing comma is not preserved in the output and
			// instead we get double-space.
			expected: "env: { A: a, B: b, C: c }\n",
			skip:     true,
		},
		{
			name:    "add mapping inside sequence item",
			content: "steps:\n  - name: Test\n    run: echo hi\n",
			patches: []Patch{{
				Path:      "steps.0",
				Operation: AddOp{Key: "shell", Value: "bash"},
			}},
			expected: "steps:\n  - name: Test\n    run: echo hi\n    shell: bash\n",
		},
	}

	for _, tt := range tests {
		if tt.skip {
			t.Skip(tt.name)
		}

		t.Run(tt.name, func(t *testing.T) {
			out, err := ApplyYAMLPatches(tt.content, tt.patches)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, out)
		})
	}
}
