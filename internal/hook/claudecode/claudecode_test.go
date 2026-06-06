package claudecode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAnalyze covers the cases the Python original was built to catch:
// bare PM verbs, exec-style PMs, wrapped invocations, bash -c "..." nesting,
// env-assignment prefixes, redirects, and explicit bypass.
func TestAnalyze(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string // PM name expected, "" for "not risky"
	}{
		{"plain npm install", "npm install foo", "npm"},
		{"npm with version", "npm install lodash@4.17.21", "npm"},
		{"npm run is not risky", "npm run dev", ""},
		{"npm ci risky", "npm ci", "npm"},
		{"yarn add", "yarn add react", "yarn"},
		{"yarn dlx", "yarn dlx some-tool", "yarn"},
		{"yarn build is not risky", "yarn build", ""},
		{"pnpm add", "pnpm add chalk", "pnpm"},
		{"pip install", "pip install requests", "pip"},
		{"pip3 install", "pip3 install requests", "pip3"},
		{"pip download", "pip download numpy", "pip"},
		{"uv add", "uv add pandas", "uv"},
		{"poetry install", "poetry install", "poetry"},

		// `npm exec` is the npx-equivalent built into npm 7+. The hook
		// only checks the verb (real spec-resolution happens at the
		// veto-Go-parser layer), so any `npm exec` invocation must
		// route through veto — even `npm exec --help`. The Go parser
		// then sees the help flag and emits no installs.
		{"npm exec is risky", "npm exec evil-pkg", "npm"},
		{"npm exec with -- separator", "npm exec -- evil-pkg", "npm"},
		{"npx with any arg is risky", "npx create-react-app foo", "npx"},
		{"npx help is fine", "npx --help", ""},
		{"npx -h is fine", "npx -h", ""},
		{"bunx is risky", "bunx some-cli", "bunx"},
		{"uvx is risky", "uvx ruff check .", "uvx"},
		{"pipx run is risky", "pipx run black .", "pipx"},

		{"veto prefix already guarded", "veto npm install foo", ""},
		{"absolute path PM", "/opt/homebrew/bin/npm install foo", "npm"},

		{"timeout wrapper", "timeout 30 npm install foo", "npm"},
		{"timeout with flags", "timeout --signal=KILL -k 5 30 npm install foo", "npm"},
		{"env wrapper", "env FOO=bar npm install foo", "npm"},
		{"env with -i flag", "env -i PATH=/usr/bin npm install foo", "npm"},
		{"sudo wrapper", "sudo npm install -g foo", "npm"},
		{"sudo with user", "sudo -u root npm install -g foo", "npm"},
		{"xargs wrapper", "xargs -n1 npm install foo", "npm"},
		{"nice wrapper", "nice -n 10 npm install foo", "npm"},
		{"nohup wrapper", "nohup npm install foo", "npm"},
		{"time wrapper", "time npm install foo", "npm"},
		{"watch wrapper", "watch -n 5 npm install foo", "npm"},

		{"bash -c inline", `bash -c "npm install foo"`, "npm"},
		{"bash -c with wrapper inside", `bash -c "timeout 30 pip install foo"`, "pip"},
		{"sh -c inline", `sh -c "yarn add react"`, "yarn"},
		{"zsh -c inline", `zsh -c "uv add pandas"`, "uv"},
		{"bash -c with separator", `bash -c "cd /tmp && npm install foo"`, "npm"},

		{"chained &&", "cd /tmp && npm install foo", "npm"},
		{"chained ;", "cd /tmp; npm install foo", "npm"},
		{"chained |", "echo y | npm install foo", "npm"},
		{"chained ||", "false || npm install foo", "npm"},

		{"env var assignment", "FOO=bar npm install foo", "npm"},
		{"two env var assignments", "FOO=bar BAZ=qux pip install requests", "pip"},
		// VETO_BYPASS has been removed from the contract. Any value of
		// the env (including the legacy "=1") must NOT disable the gate;
		// the env is treated as ordinary env-assignment noise and the
		// risky command still flags.
		{"legacy VETO_BYPASS=1 is now ignored", "VETO_BYPASS=1 npm install foo", "npm"},
		{"legacy VETO_BYPASS=0 still flags", "VETO_BYPASS=0 npm install foo", "npm"},
		{"legacy VETO_BYPASS= still flags", "VETO_BYPASS= npm install foo", "npm"},

		{"redirect operator", "npm install foo > /tmp/log 2>&1", "npm"},
		{"redirect operator with append", "pip install foo >> /tmp/log", "pip"},

		{"empty string", "", ""},
		{"just whitespace", "   ", ""},
		{"non-PM command", "ls -la /tmp", ""},
		{"not an install verb", "npm test", ""},
		{"git is not a PM", "git clone https://example.com/foo", ""},
		{"unparseable quotes", `npm install "unterminated`, ""},

		// `python -m <pm> …` is the canonical install form inside
		// virtualenvs, Dockerfiles, and most CI scripts. It MUST gate.
		// Other `python -m` modules (venv, http.server, unittest, …)
		// and bare python invocations MUST pass through.
		{"python -m pip install", "python -m pip install foo", "pip"},
		{"python3 -m pip install", "python3 -m pip install foo", "pip"},
		{"python -m pip3 install", "python -m pip3 install foo", "pip3"},
		{"python -m uv add", "python -m uv add pandas", "uv"},
		{"python -m pipx install", "python -m pipx install black", "pipx"},
		{"python -m poetry install", "python -m poetry install", "poetry"},
		{"python -m pdm add", "python -m pdm add foo", "pdm"},
		{"python -m pip via absolute path", "/usr/bin/python3 -m pip install foo", "pip"},
		{"python -m pip with verb-less argv", "python -m pip", ""},
		{"python -m pip with non-dangerous verb", "python -m pip list", ""},
		{"python -m http.server is benign", "python -m http.server 8000", ""},
		{"python -m venv is benign", "python -m venv .venv", ""},
		{"python -m unittest is benign", "python -m unittest discover", ""},
		{"plain python script is benign", "python script.py", ""},
		{"python -c snippet is benign", `python -c "print('hi')"`, ""},
		{"python -V is benign", "python -V", ""},
		{"python REPL is benign", "python", ""},
		{"python -m pip inside bash -c", `bash -c "python -m pip install foo"`, "pip"},
		{"python -m pip with wrapper", "timeout 30 python -m pip install foo", "pip"},
		{"python -m pip with env assignment", "FOO=bar python -m pip install foo", "pip"},
		{"python -m pip chained", "cd /tmp && python -m pip install foo", "pip"},

		{"go get", "go get github.com/evil/module@v1.2.3", "go"},
		{"go install", "go install github.com/evil/cmd@v0.2.0", "go"},
		{"remote go run", "go run github.com/evil/cmd@latest", "go"},
		{"go mod download", "go mod download github.com/evil/module@v1.2.3", "go"},
		{"go mod tidy", "go mod tidy", "go"},
		{"local go run", "go run ./cmd/app", "go"},
		{"go run with no target", "go run", ""},
		{"go mod edit is not gated", "go mod edit -require=example.com/mod@v1.0.0", ""},
		{"go build", "go build ./...", "go"},
		{"go test", "go test ./...", "go"},
		{"go test with run flag", "go test -run TestThing ./...", "go"},
		{"go test with global C", "go -C nested test ./...", "go"},
		{"go vet", "go vet ./...", "go"},
		{"go version is informational", "go version", ""},
		{"go env is informational", "go env", ""},

		{"cargo add", "cargo add serde", "cargo"},
		{"cargo update", "cargo update", "cargo"},
		{"cargo fetch", "cargo fetch", "cargo"},
		{"cargo install", "cargo install ripgrep", "cargo"},
		{"cargo build", "cargo build", "cargo"},
		{"cargo build with manifest path", "cargo --manifest-path nested/Cargo.toml build", "cargo"},
		{"cargo check", "cargo check", "cargo"},
		{"cargo test", "cargo test", "cargo"},
		{"cargo run", "cargo run", "cargo"},
		{"cargo bench", "cargo bench", "cargo"},
		{"cargo clippy", "cargo clippy", "cargo"},
		{"cargo version is informational", "cargo version", ""},
		{"cargo metadata is informational", "cargo metadata", ""},

		{"cargo +toolchain install", "cargo +nightly install ripgrep", "cargo"},
		{"cargo +toolchain build", "cargo +stable build", "cargo"},
		{"cargo +toolchain add", "cargo +1.75 add serde", "cargo"},
		{"cargo +toolchain version stays informational", "cargo +nightly version", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, risky := Analyze(tc.cmd)
			if tc.want == "" {
				require.False(t, risky, "expected not-risky for %q; got pm=%s tokens=%v", tc.cmd, finding.PM, finding.Tokens)
				return
			}
			require.True(t, risky, "expected risky for %q", tc.cmd)
			require.Equal(t, tc.want, finding.PM)
		})
	}
}

// TestStripWrappers exercises wrapper-stripping behavior end-to-end through
// Analyze for the more complex flag combinations. Wrappers that swallow
// the wrong number of arguments would either let a risky command through
// (false-negative) or block an innocent one (false-positive).
func TestStripWrappersComplex(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"timeout with kill-after and signal", "timeout --kill-after=5s --signal=TERM 30 npm install foo", "npm"},
		{"sudo with multiple short flags", "sudo -E -H npm install -g foo", "npm"},
		{"sudo -u user with --", "sudo -u me -- pnpm add chalk", "pnpm"},
		{"nested wrappers", "timeout 30 nice -n 10 sudo npm install foo", "npm"},
		{"env with multiple assignments", "env A=1 B=2 C=3 pip install requests", "pip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, risky := Analyze(tc.cmd)
			require.True(t, risky, "expected risky for %q", tc.cmd)
			require.Equal(t, tc.want, finding.PM)
		})
	}
}

// TestTokensSurfacedForRefusalMessage confirms the Tokens field carries
// the leaf-command (post-wrapper-stripping) so the refusal message tells
// the agent precisely what to re-issue with a `veto` prefix.
func TestTokensSurfacedForRefusalMessage(t *testing.T) {
	finding, ok := Analyze("timeout 30 npm install --save-dev lodash")
	require.True(t, ok)
	require.Equal(t, []string{"npm", "install", "--save-dev", "lodash"}, finding.Tokens)
}

// TestAnalyze_NestedBashC_UnspacedSeparators proves the analyzer
// handles `bash -c "cd /tmp;npm install foo"` — the inner shlex-and-split
// must also recover unspaced separators, not just the top-level pass.
// Regression for the L1 reviewer's first fail-OPEN finding.
func TestAnalyze_NestedBashC_UnspacedSeparators(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		pm   string
	}{
		{"semicolon_unspaced", `bash -c "cd /tmp;npm install foo"`, "npm"},
		{"and_unspaced", `bash -c "true&&npm install foo"`, "npm"},
		{"or_unspaced", `bash -c "false||npm install foo"`, "npm"},
		{"semicolon_then_chain", `bash -c "echo hi;true;npm install foo"`, "npm"},
		{"sh_dash_c_semicolon", `sh -c "cd /tmp;pip install requests"`, "pip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			finding, ok := Analyze(tc.cmd)
			require.True(t, ok, "must detect %q as risky", tc.cmd)
			require.Equal(t, tc.pm, finding.PM)
		})
	}
}

// TestAnalyze_CommandSubstitution_Refused proves $(...) / backticks /
// <(...) / >(...) are NOT silently passed; they emit a Finding so the
// hook can deny. Regression for the L1 reviewer's command-substitution
// fail-OPEN. Phase 3.1 replaces the band-aid with a real AST walk; the
// contract here must keep passing.
func TestAnalyze_CommandSubstitution_Refused(t *testing.T) {
	cases := []string{
		`echo $(npm install foo)`,
		"echo `npm install foo`",
		`diff <(echo a) <(npm install foo)`,
		`echo >(npm install foo)`,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, ok := Analyze(c)
			require.True(t, ok,
				"command substitution must be treated as risky for %q", c)
		})
	}
}

// TestAnalyze_Herestring_Refused — `sh <<< 'npm install foo'`. The <<<
// herestring is opaque to shlex, and the legacy redirect-stripper
// discarded the payload entirely. Phase 1.2 surfaces this as risky.
func TestAnalyze_Herestring_Refused(t *testing.T) {
	cases := []string{
		`sh <<< 'npm install foo'`,
		`bash <<< "pip install requests"`,
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, ok := Analyze(c)
			require.True(t, ok, "<<< herestrings must not silently drop the payload (%q)", c)
		})
	}
}

// TestPythonDashMTokensPreserveOriginalInvocation confirms the
// corrected command the agent gets back is `veto python -m pip install
// foo`, not `veto pip install foo`. The interpreter prefix is
// load-bearing: `python -m pip` resolves pip against the running
// interpreter (venv scope), so dropping it would silently break the
// install.
func TestPythonDashMTokensPreserveOriginalInvocation(t *testing.T) {
	finding, ok := Analyze("python -m pip install foo")
	require.True(t, ok)
	require.Equal(t, "pip", finding.PM)
	require.Equal(t, []string{"python", "-m", "pip", "install", "foo"}, finding.Tokens)
}
