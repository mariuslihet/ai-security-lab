# Contributing

Keep the demo offline. Do not introduce provider SDK or external tool calls into demo execution. Keep fixture response selection independent from guardrail settings. Preserve raw response, delivered content and objective evidence separately.

Add versioned YAML fixtures with unique IDs, explicit objectives, success/safe assertions, synthetic provenance and expected fixture behavior. Use messages for multi-turn cases, documents for untrusted context, canary for synthetic secret tests and forbidden_tools for sandbox proposals. Schema validation rejects unknown fields and duplicate IDs. Never store real credentials in fixtures.

Run python -m pytest and python examples/ci_cd_integration.py. Add regression tests for behavioral changes, especially denominators, errors, cancellation and output escaping. All HTTP tests must use a temporary database. Update README counts and versions when changing fixtures.

Do not label local timings or estimated tokens as provider measurements. Do not infer compliance, calibrated confidence or real-world model rankings from synthetic data.
