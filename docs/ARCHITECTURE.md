# Demo architecture v2

Browser or CLI → RunService → versioned fixtures → SecurityHarness → DemoLLMClient → objective assertions → metrics → SQLite evidence → JSON / Markdown / printable view.

There is one verdict pipeline. Dashboard requests create bounded background jobs; polling reads stored partial evidence. CLI executes the same service synchronously. The WebSocket adapter exposes the same evidence, without independent scoring logic.

Guardrails inspect input and retrieved documents before dispatch, and generated output and sandbox tool permissions after dispatch. Raw response and delivered content are recorded separately. Model behavior does not depend on guardrail toggles. Multi-turn fixtures retain user/assistant history, and inspect each user turn. No tool executor or external HTTP target is present.

RunRequest validates provider label, profile, seed, suite, repetitions and budgets. The service has two workers and at most four accepted jobs. Cancellation is checked between tests. Time and estimated-token limits are checked before dispatch; one synchronous in-flight demo probe completes before cancellation. Interrupted jobs are marked on service restart.

Each run stores its configuration, fixture fingerprint, versions, status, partial summaries, evidence, timestamps, local processing duration, estimated tokens and zero actual API cost. Each SQLite operation closes its connection. Unknown suite names never become filesystem paths. Documentation uses an allowlist. Report HTML escapes all user-controlled content. The shipped dashboard launcher binds to loopback.

The SQLite file is local application state, not a multi-tenant production database. No authentication, remote deployment or commercial-provider benchmarking is claimed. Existing provider SDK adapters are outside the supported demo flow.
