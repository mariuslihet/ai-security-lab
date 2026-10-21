# Demo scope and threat taxonomy

Version: OWASP Top 10 for LLM Applications 2025. The demo illustrates direct/indirect prompt injection (LLM01), sensitive information disclosure (LLM02), system prompt leakage (LLM07), and excessive agency via sandbox proposals (LLM06). Retrieved document injection is an LLM01 scenario; it does not establish vector or embedding security (LLM08).

The target is a deterministic local fixture engine. There are no actual provider calls, production credentials, vector stores, authorization backends, email sends, deletions or external tool executions. Tool proposals have executed=false, including in the unguarded arm. A forbidden proposal demonstrates an agent policy violation, not an actual external compromise.

The lab itself receives adversarial strings. Its interface escapes them, exposes only allowlisted documentation and stored run IDs, validates requests, binds to loopback by default and does not enable CORS. Exported evidence deliberately includes synthetic secrets. Do not supply real protected data.

This is a workflow demonstration, not a certification of OWASP coverage or regulatory compliance. Future live and application-target evaluation requires a separate threat model, adapter contract, privacy review and end-to-end validation.
