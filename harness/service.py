"""Bounded offline jobs, persisted evidence and paired comparisons."""

from __future__ import annotations
import hashlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, field_validator
from core.demo_client import DemoLLMClient
from harness.loader import load_all_suites
from harness.models import SecurityTestCase
from harness.applications import ApplicationDefinition
from harness.runner import SecurityHarness
from evals.evaluator import SecurityEvaluator

ROOT = Path(__file__).resolve().parent.parent


class GuardrailPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    injection: bool = True
    pii: bool = True
    canary: bool = True
    content: bool = True
    enforce_input: bool = True
    enforce_output: bool = True

    def engine(self):
        from guardrails.engine import GuardrailEngine
        from guardrails.input.prompt_injection import PromptInjectionGuardrail
        from guardrails.input.pii_detector import PIIDetectorGuardrail
        from guardrails.output.canary_checker import CanaryLeakGuardrail
        from guardrails.output.content_safety import ContentSafetyGuardrail

        inputs, outputs = [], []
        if self.injection:
            inputs.append(PromptInjectionGuardrail())
        if self.pii:
            inputs.append(PIIDetectorGuardrail())
            outputs.append(PIIDetectorGuardrail(name="OutputPIIDetector"))
        if self.canary:
            outputs.append(CanaryLeakGuardrail())
        if self.content:
            outputs.append(ContentSafetyGuardrail())
        return GuardrailEngine(inputs, outputs, self.enforce_input, self.enforce_output)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    application: ApplicationDefinition | None = None
    application_id: str | None = None
    policy_id: str | None = None
    scenario: Literal["suite", "support", "documents", "agent"] = "suite"
    policy: GuardrailPolicy = Field(default_factory=GuardrailPolicy)
    provider: Literal["openai", "anthropic", "azure", "bedrock"] = "openai"
    profile: Literal["balanced", "resilient", "permissive"] = "balanced"
    suite: str = Field(default="prompt_injections", max_length=100)
    seed: int = Field(default=42, ge=0, le=2147483647)
    guardrails: bool = True
    compare: bool = False
    repetitions: int = Field(default=1, ge=1, le=5)
    max_tests: int = Field(default=500, ge=1, le=1000)
    max_tokens: int = Field(default=100000, ge=1, le=1000000)
    max_seconds: int = Field(default=60, ge=1, le=300)
    custom_case: SecurityTestCase | None = None
    named_policies: dict[str, GuardrailPolicy] = Field(
        default_factory=dict, max_length=3
    )

    @field_validator("named_policies")
    @classmethod
    def validate_names(cls, value):
        import re

        if any(
            not re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", name)
            or name in ("baseline", "defended")
            for name in value
        ):
            raise ValueError(
                "Use distinct policy names of 1–40 lowercase letters, digits, hyphens or underscores; baseline/defended are reserved"
            )
        return value


class RunStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT NOT NULL, body TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.execute("PRAGMA busy_timeout=15000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, record):
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO runs VALUES (?, ?, ?)",
                (
                    record["id"],
                    record["created_at"],
                    json.dumps(record, ensure_ascii=False),
                ),
            )

    def get(self, identifier):
        with self.connect() as db:
            row = db.execute(
                "SELECT body FROM runs WHERE id=?", (identifier,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit=50, offset=0):
        with self.connect() as db:
            rows = db.execute(
                "SELECT body FROM runs ORDER BY created DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]


class RunService:
    def __init__(self, store, data_dir=ROOT / "data"):
        self.store, self.data_dir = store, Path(data_dir)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="demo-run")
        self.capacity = threading.BoundedSemaphore(4)
        self.lock = threading.Lock()
        self.cancelled = {}
        # An interrupted process never leaves an apparently active run forever.
        for record in store.list(limit=10000):
            if record["status"] in ("queued", "running"):
                record.update(
                    status="interrupted",
                    error="Application restarted before completion.",
                )
                store.save(record)

    def catalog(self):
        return [
            {
                "id": name,
                "name": name.replace("_", " ").title(),
                "count": len(cases),
                "adversarial": sum(c.is_adversarial for c in cases),
                "languages": sorted({c.language for c in cases}),
            }
            for name, cases in load_all_suites(self.data_dir).items()
        ]

    def cases(self, request):
        if request.application:
            from harness.applications import application_cases

            cases = application_cases(request.application)
        elif request.scenario != "suite":
            from harness.scenarios import scenario_cases

            cases = scenario_cases(request.scenario)
        elif request.custom_case:
            cases = [request.custom_case]
        else:
            suites = load_all_suites(self.data_dir)
            if request.suite == "all":
                cases = [c for group in suites.values() for c in group]
            elif request.suite in suites:
                cases = suites[request.suite]
            else:
                raise ValueError("Unknown suite")
        if not cases:
            raise ValueError("The selected suite is empty")
        return cases * request.repetitions

    def start(self, request, background=True, cases_override=None, source_run=None):
        cases = self.cases(request) if cases_override is None else cases_override
        if not cases:
            raise ValueError("No fixture evidence to replay")
        arms = (
            [("baseline", False, request.policy)]
            + [(name, True, policy) for name, policy in request.named_policies.items()]
            if request.named_policies
            else [
                ("baseline" if not enabled else "defended", enabled, request.policy)
                for enabled in (
                    [False, True] if request.compare else [request.guardrails]
                )
            ]
        )
        planned = len(cases) * len(arms)
        if planned > request.max_tests:
            raise ValueError(
                f"Run requires {planned} tests; configured limit is {request.max_tests}"
            )
        if not self.capacity.acquire(blocking=False):
            raise RuntimeError(
                "Demo job queue is full; wait for an active run to finish"
            )
        identifier = str(uuid4())
        cancel = threading.Event()
        with self.lock:
            self.cancelled[identifier] = cancel
        manifest = [c.model_dump(mode="json") for c in cases]
        record = {
            "source_run": source_run,
            "id": identifier,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "queued",
            "execution_mode": "demo",
            "notice": "Synthetic fixtures; no commercial model measurements or external actions.",
            "config": request.model_dump(mode="json"),
            "fixture_snapshot": manifest,
            "dataset_sha256": hashlib.sha256(
                json.dumps(manifest, sort_keys=True).encode()
            ).hexdigest(),
            "engine_version": "2.3.0",
            "evaluator_version": "objective-v3",
            "dataset_version": "2.3",
            "completed": 0,
            "planned": planned,
            "arms": {},
            "estimated_tokens": 0,
            "actual_cost_usd": 0,
            "error": None,
        }
        self.store.save(record)
        if background:
            self.pool.submit(self._execute, record, request, cases, arms, cancel)
        else:
            self._execute(record, request, cases, arms, cancel)
        return identifier

    def _execute(self, record, request, cases, arms, cancel):
        started = time.perf_counter()
        record["status"] = "running"
        self.store.save(record)
        try:
            for name, enabled, policy in arms:
                results = []
                client = DemoLLMClient(request.provider, request.profile, request.seed)
                harness = SecurityHarness(
                    client,
                    guardrail_engine=policy.engine(),
                    use_guardrails=enabled,
                )
                for case in cases:
                    if cancel.is_set():
                        record["status"] = "cancelled"
                        break
                    if time.perf_counter() - started >= request.max_seconds:
                        record.update(
                            status="limit_reached", error="Execution time limit reached"
                        )
                        break
                    # Conservative whitespace bound includes multi-turn context replay,
                    # fixture output and safety margin, before dispatching the next test.
                    words = len(case.prompt.split()) + sum(
                        len(d.split()) for d in case.documents
                    )
                    words += (
                        len((case.system_prompt or "").split())
                        + len((case.canary or "").split())
                        + 30
                    )
                    turns = max(1, len(case.messages))
                    words += sum(len(m["content"].split()) for m in case.messages)
                    fixture_words = (
                        sum(
                            len(s.split())
                            for s in case.success_contains + case.safe_contains
                        )
                        + len((case.canary or "").split())
                        + 60
                    )
                    estimate = (words + max(512, fixture_words)) * turns * turns
                    if record["estimated_tokens"] + estimate > request.max_tokens:
                        record.update(
                            status="limit_reached",
                            error="Estimated token budget would be exceeded",
                        )
                        break
                    result = harness.run_test(case)
                    result.expected_verdicts = case.expected_verdicts.get(
                        "defended" if enabled else "baseline", []
                    )
                    if result.expected_verdicts:
                        result.expectation_met = (
                            result.verdict in result.expected_verdicts
                        )
                    results.append(result)
                    record["completed"] += 1
                    record["estimated_tokens"] += sum(
                        e.get("tokens_estimated", 0) for e in result.events
                    )
                    summary = SecurityEvaluator().evaluate(
                        results, request.provider, request.profile, enabled
                    )
                    record["arms"][name] = summary.model_dump(mode="json")
                    self.store.save(record)
                if record["status"] != "running":
                    break
            if record["status"] == "running":
                incomplete = any(
                    a["metrics"]["errors"] or a["metrics"]["inconclusive"]
                    for a in record["arms"].values()
                )
                regression = any(
                    r.get("expectation_met") is False
                    for a in record["arms"].values()
                    for r in a["results"]
                )
                record["status"] = (
                    "needs_review" if incomplete or regression else "completed"
                )
        except Exception as exc:
            record.update(status="error", error=str(exc))
        finally:
            record["finished_at"] = datetime.now(timezone.utc).isoformat()
            record["duration_ms"] = round((time.perf_counter() - started) * 1000, 3)
            self.store.save(record)
            with self.lock:
                self.cancelled.pop(record["id"], None)
            self.capacity.release()

    def cancel(self, identifier):
        with self.lock:
            event = self.cancelled.get(identifier)
            if event:
                event.set()
        return bool(event)

    def close(self):
        with self.lock:
            for event in self.cancelled.values():
                event.set()
        self.pool.shutdown(wait=True, cancel_futures=False)
