# Functional QA — 22 October 2026

Target: http://127.0.0.1:8501/ (offline fictional data).

- Backend: 88 passing tests, including ownership, approvals, state isolation, all profiles, verify snapshot/lineage and source preservation.
- Browser: guided unprotected/protected comparison, approved refund, missing-approval evidence, verify action, policy experiment, history comparison, snapshot replay, and printable report content verified.
- Guided results: baseline 3/3 attacks exposed; protected 0/3; approved refund allowed; 0/1 benign requests blocked.
- Browser cancellation: stopped at 118/340 with partial evidence retained.
- JSON/Markdown controls clicked; their response content and exports are covered by HTTP tests. Printable report headings and regression markers checked in browser.
- JavaScript syntax and diff whitespace checks pass; offline correctness gate passes.
- Presentation issues found and fixed: object-valued timeline action rendering and missing business-rule evidence text.

Visual regression verdict: INCONCLUSIVE (no committed screenshot baseline). Multi-viewport, Core Web Vitals, console/network instrumentation, axe and manual keyboard/screen-reader auditing were not completed. This is a functional verification report, not an accessibility certification or production readiness assessment.
