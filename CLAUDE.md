# rules

- always load the following skills before doing work on the code:
    - brynsk-architecture
    - brynsk-go-concurrency
    - allora-go-style-guide
    - engineering-cli-tools

- always work on a git worktree on a separate branch.  do not work on master/main.

- if tasked with a large endeavour, favor delegating work to a subagent, but not multiple.  a single subagent working inline provides breathing room for the orchestrator's context window while avoiding the footguns of having many subagents working in parallel.

- when running `go build`, `go test`, `go vet`, or any `make` target that compiles Go in this repo, you MUST bypass veto routing.  pick the method that works for your current install state:
    - **go not yet Layer-4-wrapped**: prefix with `VETO_PATH=`, e.g. `VETO_PATH= go test ./...`.  the shell finds `go` via PATH; with empty `VETO_PATH` veto disengages.
    - **go IS Layer-4-wrapped** (the default once `veto install-wrappers` has run): use the `.veto-original` sibling directly, e.g. `VETO_PATH= /opt/homebrew/bin/go.veto-original test ./...` (or whichever real go you prefer — `~/.local/share/mise/installs/go/<ver>/bin/go.veto-original` works too).  `VETO_PATH=` alone is not enough here because the wrap symlink routes the FIRST exec through veto before any env var matters.
- without one of these bypasses, every Go subprocess (`go tool compile`, `go tool link`, etc.) gets routed through veto and triggers a full intel-store refresh, stretching a sub-second test run into a multi-minute flood of `intel store refreshed` log lines that looks like an infinite loop.  this is not a bug to investigate — it is the expected cost of veto being installed.  do NOT spawn background tasks that run uncapped `veto go ...` builds; they will swamp output and burn time.


## Task tracking

this project uses `beads_rust` for tack tracking (cli tool: `br`).

if the user mentions anything regarding task tracking (adding, working on, modifying an issue/ticket, etc), you *MUST* load the `br` skill.

when adding beads, always organize things by epic (which additionally requires an `epic:<name>` label). always express task dependencies/blockers.

any time you finish work, make sure its associated bead is marked as done.  this includes epics.

## Things to keep up to date

- `veto doctor` must always be up to date with current capabilities.
- `veto install*` commands (especially `veto install-all`) must always do what they claim.  if new, granular install commands need to be added to reflect a new capability, make sure to do so.
- `README.md` should always be reflective of capabilities.  it must offer a thorough onboarding to the tool for new and existing users (veto iterates quickly -- there should always be a suggested command set near the top of the file for upgrading an existing installation).
