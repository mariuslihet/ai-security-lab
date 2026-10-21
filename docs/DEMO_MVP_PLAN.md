# Demo MVP implementation

Offline demonstration: provider names identify simulated targets, not measurements
or rankings of commercial models. Payloads, secrets, tool calls and token counts
are synthetic. No external tools execute.

Sequence: typed evidence and versioned datasets; shared harness and objective
evaluation; correct metrics; persisted runs and limits; dashboard, comparisons and
history; offline regression gates, packaging, documentation and browser verification.

Acceptance: no credentials or network; selected suites actually execute; guardrails
affect intervention, never fixture responses; success requires objective evidence;
errors and unknowns never become passes; empty runs never show 100%; UI and exports
use the same stored result; safely rendered content; no compliance or calibrated
confidence claims.

Implemented: all six stages. The demo includes 68 fixtures in nine suites, three
provider-independent response profiles, objective evaluation, paired comparison,
benign controls, error and ambiguous fixtures, per-turn evidence, sandbox proposals,
SQLite history, immutable fixture snapshots for replay, bounded/cancellable jobs,
custom probes, escaped JSON/Markdown/print exports, and offline regression checks.

Verification includes automated engine/service/HTTP tests, an offline correctness
gate, JavaScript syntax checks, installed-wheel asset/data smoke checks and manual
browser checks. No live-provider security assessment is part of this release.
