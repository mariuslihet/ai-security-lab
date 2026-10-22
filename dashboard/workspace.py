"""Local persisted applications, policy versions, findings, and selected reports."""

import json
from uuid import uuid4
from datetime import datetime, timezone
from html import escape
from typing import Literal
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, ConfigDict
from harness.applications import ApplicationDefinition
from harness.service import GuardrailPolicy, RunRequest


class PolicyDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    policy: GuardrailPolicy = Field(default_factory=GuardrailPolicy)


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "resolved", "accepted"] = "open"
    notes: str = Field(default="", max_length=5000)
    verification_run: str | None = None


class ReportSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="Application security review", max_length=200)
    audience: Literal["executive", "engineering"] = "executive"
    finding_ids: list[str] = Field(min_length=1, max_length=100)


def workspace_router(service):
    router = APIRouter(prefix="/api/workspace")

    def db():
        store = service().store
        with store.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS workspace (id TEXT PRIMARY KEY, kind TEXT NOT NULL, body TEXT NOT NULL)"
            )
        return store

    def save(kind, body, identifier=None):
        identifier = identifier or str(uuid4())
        body = {**body, "id": identifier}
        with db().connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO workspace VALUES (?,?,?)",
                (identifier, kind, json.dumps(body)),
            )
        return body

    def get(identifier, kind):
        with db().connect() as conn:
            row = conn.execute(
                "SELECT body FROM workspace WHERE id=? AND kind=?", (identifier, kind)
            ).fetchone()
        if not row:
            raise HTTPException(404, "Workspace item not found")
        return json.loads(row[0])

    def listing(kind):
        with db().connect() as conn:
            rows = conn.execute(
                "SELECT body FROM workspace WHERE kind=? ORDER BY rowid DESC", (kind,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def run(identifier):
        record = service().store.get(identifier)
        if record is None:
            raise HTTPException(404, "Run not found")
        return record

    @router.get("/applications")
    def apps():
        return listing("application")

    @router.post("/applications", status_code=201)
    def add_app(body: ApplicationDefinition):
        return save(
            "application",
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "definition": body.model_dump(),
            },
        )

    @router.get("/policies")
    def policies():
        return listing("policy")

    @router.post("/policies", status_code=201)
    def add_policy(body: PolicyDefinition):
        # Each save is an immutable version. References in old runs never change.
        return save(
            "policy",
            {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "definition": body.model_dump(),
            },
        )

    @router.post("/applications/{identifier}/run", status_code=202)
    def start_app(identifier: str, request: RunRequest):
        definition = get(identifier, "application")["definition"]
        config = request.model_dump()
        config.update(
            application=definition,
            application_id=identifier,
            scenario=definition["scenario"],
        )
        if request.policy_id:
            config["policy"] = get(request.policy_id, "policy")["definition"]["policy"]
        try:
            key = service().start(RunRequest.model_validate(config))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc
        return {"id": key}

    @router.get("/findings")
    def findings():
        return listing("finding")

    @router.post("/findings/import/{identifier}")
    def import_findings(identifier: str):
        record = run(identifier)
        if record["status"] in ("queued", "running"):
            raise HTTPException(409, "Wait for execution to finish")
        imported = []
        existing = listing("finding")
        for arm, summary in record["arms"].items():
            for result in summary["results"]:
                if result["verdict"] not in ("EXPOSED", "FALSE_POSITIVE"):
                    continue
                case = result["test_case"]
                scope = record["config"].get("application_id") or record["config"].get(
                    "scenario", "suite"
                )
                match = next(
                    (
                        f
                        for f in existing
                        if f["scope"] == scope
                        and f["case_id"] == case["id"]
                        and f["arm"] == arm
                    ),
                    None,
                )
                occurrence = {
                    "run_id": identifier,
                    "verdict": result["verdict"],
                    "evidence": result["evidence"],
                    "notes": result["notes"],
                }
                if match and any(
                    o["run_id"] == identifier for o in match["occurrences"]
                ):
                    continue
                body = match or dict(
                    scope=scope,
                    case_id=case["id"],
                    arm=arm,
                    title=case["name"],
                    severity=case["severity"],
                    status="open",
                    notes="",
                    occurrences=[],
                    verification_history=[],
                )
                body["occurrences"].append(occurrence)
                body["status"] = "open"
                saved = save("finding", body, body.get("id"))
                imported.append(saved)
                if not match:
                    existing.append(saved)
        return imported

    @router.patch("/findings/{identifier}")
    def update(identifier: str, body: FindingUpdate):
        finding = get(identifier, "finding")
        if body.verification_run:
            verification = run(body.verification_run)
            verification_arm = "defended" if "defended" in verification["arms"] else finding["arm"]
            matches = [
                r
                for arm, a in verification["arms"].items()
                if arm == verification_arm
                for r in a["results"]
                if r["test_case"]["id"] == finding["case_id"]
            ]
            if not matches or verification["status"] not in (
                "completed",
                "needs_review",
            ):
                raise HTTPException(
                    422, "Verification needs a completed matching probe and policy arm"
                )
            original = run(finding["occurrences"][-1]["run_id"])
            if original["dataset_sha256"] != verification["dataset_sha256"]:
                raise HTTPException(422, "Verification fixture snapshot differs")
            acceptable = ("ALLOWED",) if finding["occurrences"][-1]["verdict"] == "FALSE_POSITIVE" else ("BLOCKED", "REFUSED", "SAFE", "ALLOWED")
            passed = all(
                r["verdict"] in acceptable
                for r in matches
            )
            finding["verification_history"].append(
                {"run_id": body.verification_run, "passed": passed}
            )
            if body.status == "resolved" and not passed:
                raise HTTPException(
                    422, "Verification still contains an unsafe or unknown outcome"
                )
        elif body.status == "resolved":
            raise HTTPException(
                422, "Attach a successful matching verification run before resolving"
            )
        finding.update(status=body.status, notes=body.notes)
        return save("finding", finding, identifier)

    @router.post("/reports", response_class=HTMLResponse)
    def report(body: ReportSelection):
        chosen = [get(i, "finding") for i in dict.fromkeys(body.finding_ids)]
        e = lambda v: escape(str(v))
        rows = "".join(
            f"<article><h2>{e(f['title'])}</h2><p>{e(f['severity'])} · {e(f['status'])} · {e(f['scope'])}</p><p>{e(f['notes'])}</p>"
            + (
                f"<pre>{e(json.dumps(f,indent=2))}</pre>"
                if body.audience == "engineering"
                else f"<p>{len(f['occurrences'])} recorded occurrences; {len(f['verification_history'])} verification records.</p>"
            )
            + "</article>"
            for f in chosen
        )
        return (
            '<!doctype html><html lang="en"><meta charset="utf-8"><title>'
            + e(body.title)
            + "</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}article{border-top:1px solid #ccc;padding:15px 0}@media print{button{display:none}}</style><h1>"
            + e(body.title)
            + '</h1><p>OFFLINE DEMO · Fictional data. This report does not establish real-model security or compliance.</p><button onclick="print()">Print / Save PDF</button>'
            + rows
            + "</html>"
        )

    return router
