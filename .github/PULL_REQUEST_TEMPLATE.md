## Summary of Changes
Provide a brief explanation of what this pull request introduces or fixes.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (e.g. new probe suite, new guardrail rule, reporting upgrade)
- [ ] Refactor or performance enhancement
- [ ] Documentation update
- [ ] CI / GitHub Actions configuration

## Testing & Verification
Describe the tests you ran to verify your changes:
- [ ] Pytest suite passes: `pytest -v` (26+ tests)
- [ ] Verified offline diagnostic fallback mode works without live API keys
- [ ] Dashboard simulation & WebSocket traces verified (if frontend/app modified)
- [ ] YAML datasets validated against `SecurityTestCase` schema

## Checklist
- [ ] Code follows project conventions (type annotations, docstrings, no hardcoded model names, no emojis in code).
- [ ] All new files or modified functions include appropriate tests.
- [ ] Documentation updated in `README.md` and relevant `docs/*.md` specifications.
