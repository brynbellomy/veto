# rules

- always load the following skills before doing work on the code:
    - brynsk-architecture
    - brynsk-go-concurrency
    - allora-go-style-guide
    - engineering-cli-tools

- always work on a git worktree on a separate branch.  do not work on master/main.

- if tasked with a large endeavour, favor delegating work to a subagent, but not multiple.  a single subagent working inline provides breathing room for the orchestrator's context window while avoiding the footguns of having many subagents working in parallel.


## Task tracking

this project uses `beads_rust` for tack tracking (cli tool: `br`).

if the user mentions anything regarding task tracking (adding, working on, modifying an issue/ticket, etc), you *MUST* load the `br` skill.

when adding beads, always organize things by epic (which additionally requires an `epic:<name>` label). always express task dependencies/blockers.

any time you finish work, make sure its associated bead is marked as done.
