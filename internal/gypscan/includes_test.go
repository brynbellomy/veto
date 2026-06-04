package gypscan_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/brynbellomy/veto/internal/gypscan"
)

func TestParseIncludePaths(t *testing.T) {
	cases := []struct {
		name string
		gyp  string
		want []string
	}{
		{
			name: "flat includes array",
			gyp:  `{ "includes": ["common.gypi", "build/config.gypi"] }`,
			want: []string{"common.gypi", "build/config.gypi"},
		},
		{
			name: "multiple arrays",
			gyp: `{
  "includes": ["root.gypi"],
  "targets": [{ "target_name": "x", "includes": ["targets/target.gypi"] }]
}`,
			want: []string{"root.gypi", "targets/target.gypi"},
		},
		{
			name: "single and double quotes",
			gyp:  `{ 'includes': ['single.gypi', "double.gypi"] }`,
			want: []string{"single.gypi", "double.gypi"},
		},
		{
			name: "no includes",
			gyp:  `{ "targets": [] }`,
			want: nil,
		},
		{
			name: "computed include excluded",
			gyp:  `{ "includes": ["safe.gypi", "<!(node include-path.js)"] }`,
			want: []string{"safe.gypi"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, gypscan.ParseIncludePaths([]byte(tc.gyp)))
		})
	}
}
