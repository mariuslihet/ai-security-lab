"""Local-only demo control plane backed by the shared run service."""

from __future__ import annotations
import asyncio
import json
import os
import threading
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from core.demo_client import PROVIDERS, PROFILES
from guardrails.engine import GuardrailEngine
from harness.service import RunService, RunStore, RunRequest, ROOT
from harness.models import SecurityTestCase
from evals.evaluator import SecurityEvaluationSummary
from reports.markdown import MarkdownReportGenerator
from reports.html_report import render_run_report
from pydantic import BaseModel, Field


class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)


def create_app(db_path=None):
    @asynccontextmanager
    async def lifespan(app):
        yield
        if app.state.service is not None:
            app.state.service.close()

    app = FastAPI(title="AI Security Lab · Demo", version="2.3.0", lifespan=lifespan)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"],
    )
    app.state.service = None
    init_lock = threading.Lock()

    def service():
        with init_lock:
            if app.state.service is None:
                app.state.service = RunService(
                    RunStore(
                        db_path
                        or os.getenv("AI_SECURITY_LAB_DB")
                        or Path.cwd() / "reports_output" / "demo_runs.sqlite3"
                    )
                )
        return app.state.service

    def record(identifier):
        value = service().store.get(identifier)
        if value is None:
            raise HTTPException(404, "Run not found")
        return value

    def markdown(value):
        lines = [
            f"# Demo run {value['id']}",
            "",
            value["notice"],
            "",
            f"Status: {value['status']}; executed {value['completed']} / {value['planned']}",
            f"Dataset SHA256: {value['dataset_sha256']}",
            f"Engine: {value['engine_version']}; evaluator: {value['evaluator_version']}",
            f"Configuration: {json.dumps(value['config'],ensure_ascii=False)}",
            "",
        ]
        for name, summary in value["arms"].items():
            lines.extend(
                [
                    f"## {name.title()}",
                    "",
                    MarkdownReportGenerator().generate(
                        SecurityEvaluationSummary.model_validate(summary)
                    ),
                    "",
                ]
            )
        if not value["arms"]:
            lines.append("No scored evidence available. Security metrics: N/A.")
        return "\n".join(lines)

    @app.get("/", response_class=HTMLResponse)
    def home():
        return (ROOT / "dashboard/templates/index.html").read_text(encoding="utf-8")

    @app.get("/api/status")
    def status():
        return {
            "status": "healthy",
            "execution_mode": "demo",
            "network_calls": False,
            "providers": [
                {"id": k, "name": v, "configured": True, "mode": "simulated"}
                for k, v in PROVIDERS.items()
            ],
            "profiles": list(PROFILES),
            "scenarios": __import__(
                "harness.scenarios", fromlist=["SCENARIOS"]
            ).SCENARIOS,
            "suites": service().catalog(),
        }

    @app.get("/api/suites")
    def suites():
        return service().catalog()

    @app.post("/api/runs", status_code=202)
    def start(request: RunRequest):
        try:
            identifier = service().start(request)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc
        return {"id": identifier, "execution_mode": "demo"}

    @app.get("/api/runs")
    def history(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        return [
            {k: v for k, v in r.items() if k not in ("arms", "fixture_snapshot")}
            | {"metrics": {name: a["metrics"] for name, a in r["arms"].items()}}
            for r in service().store.list(limit, offset)
        ]

    @app.get("/api/compare")
    def compare(before: str, after: str):
        from evals.comparison import compare_runs

        return compare_runs(record(before), record(after))

    @app.post("/api/runs/{identifier}/verify", status_code=202)
    def verify(identifier: str):
        old = record(identifier)
        snapshot = old.get("fixture_snapshot", [])
        if not snapshot or any("demo_response" not in c for c in snapshot):
            raise HTTPException(
                409, "Fresh fixture snapshots are required for verification."
            )
        config = {
            **old["config"],
            "policy": {},
            "named_policies": {},
            "guardrails": True,
            "compare": False,
        }
        try:
            new_id = service().start(
                RunRequest.model_validate(config),
                cases_override=[SecurityTestCase.model_validate(c) for c in snapshot],
                source_run=identifier,
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc
        return {
            "id": new_id,
            "source_run": identifier,
            "notice": "Full protection rerun includes original benign controls; inspect results, not just execution status.",
        }

    @app.get("/api/runs/{identifier}")
    def get_run(identifier: str):
        return record(identifier)

    @app.post("/api/runs/{identifier}/cancel")
    def cancel(identifier: str):
        record(identifier)
        return {"cancellation_requested": service().cancel(identifier)}

    @app.post("/api/runs/{identifier}/replay", status_code=202)
    def replay(identifier: str):
        old = record(identifier)
        request = RunRequest.model_validate(old["config"])
        if any("demo_response" not in c for c in old.get("fixture_snapshot", [])):
            raise HTTPException(
                409,
                "This older run predates explicit response fixtures. Start a fresh evaluation; its saved report remains available.",
            )
        if not old.get("fixture_snapshot"):
            raise HTTPException(
                409, "This older run has no fixture snapshot. Start a fresh evaluation."
            )
        try:
            cases = [
                SecurityTestCase.model_validate(c) for c in old["fixture_snapshot"]
            ]
            identifier = service().start(request, cases_override=cases)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(429, str(exc)) from exc
        return {"id": identifier, "execution_mode": "demo"}

    @app.get("/api/runs/{identifier}/export.json")
    def export_json(identifier: str):
        return JSONResponse(
            record(identifier),
            headers={
                "Content-Disposition": f'attachment; filename="demo-{safe_id(identifier)}.json"'
            },
        )

    @app.get("/api/runs/{identifier}/export.md")
    def export_md(identifier: str):
        return PlainTextResponse(
            markdown(record(identifier)),
            headers={
                "Content-Disposition": f'attachment; filename="demo-{safe_id(identifier)}.md"'
            },
        )

    @app.get("/reports/{identifier}", response_class=HTMLResponse)
    def report_view(identifier: str):
        return HTMLResponse(render_run_report(record(identifier)))

    @app.post("/api/check-prompt")
    def check(request: PromptRequest):
        return GuardrailEngine().inspect_input(request.prompt).model_dump(mode="json")

    @app.get("/api/docs")
    def docs():
        return [
            {"id": p.stem, "title": p.stem.replace("_", " ").title()}
            for p in sorted((ROOT / "docs").glob("*.md"))
        ]

    @app.get("/api/docs/{doc_id}")
    def doc(doc_id: str):
        available = {p.stem: p for p in (ROOT / "docs").glob("*.md")}
        if doc_id not in available:
            raise HTTPException(404, "Document not found")
        return PlainTextResponse(available[doc_id].read_text(encoding="utf-8"))

    @app.websocket("/ws/simulate")
    async def ws(websocket: WebSocket):
        # Legacy transport: the exact same request and harness, no alternate verdict logic.
        from urllib.parse import urlparse

        origin = websocket.headers.get("origin")
        if origin and urlparse(origin).hostname not in (
            "127.0.0.1",
            "localhost",
            "::1",
            "testserver",
        ):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        try:
            payload = await websocket.receive_json()
            request = RunRequest.model_validate(payload)
            identifier = await asyncio.to_thread(service().start, request, False)
            value = record(identifier)
            for arm, summary in value["arms"].items():
                for result in summary["results"]:
                    for event in result["events"]:
                        await websocket.send_json(
                            {
                                **event,
                                "arm": arm,
                                "execution_mode": "demo",
                                "run_id": identifier,
                            }
                        )
            await websocket.send_json(
                {
                    "stage": "RUN_COMPLETE",
                    "run_id": identifier,
                    "status": value["status"],
                    "execution_mode": "demo",
                }
            )
        except WebSocketDisconnect:
            return
        except (ValueError, RuntimeError) as exc:
            await websocket.send_json({"stage": "ERROR", "message": str(exc)})
        finally:
            try:
                await websocket.close()
            except RuntimeError:
                pass

    from dashboard.workspace import workspace_router

    app.include_router(workspace_router(service))

    app.mount(
        "/static", StaticFiles(directory=ROOT / "dashboard/static"), name="static"
    )
    return app


def safe_id(value):
    from uuid import UUID

    return str(UUID(value))


app = create_app()


def start_dashboard(host="127.0.0.1", port=8501, open_browser=True):
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(
            "Demo dashboard is local-only. Use 127.0.0.1, localhost or ::1."
        )
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
