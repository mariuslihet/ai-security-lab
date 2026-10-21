"""Legacy event import, clearly separated from stored evidence-based run reports."""

from datetime import datetime, timezone
from uuid import uuid4


class SimulationReportGenerator:
    def generate_from_events(
        self, events, provider, model, attack_type, guardrails_enabled, run_number=1
    ):
        completed = [
            e for e in events if e.get("stage") in ("COMPLETE", "PROBE_COMPLETE")
        ]
        batch = next(
            (e for e in reversed(events) if e.get("stage") == "BATCH_COMPLETE"), None
        )
        valid = [
            e
            for e in completed
            if e.get("result") in ("EXPOSED", "BLOCKED", "REFUSED", "SAFE")
        ]
        exposed = sum(e.get("result") == "EXPOSED" for e in valid)
        verdict = "EXPOSED" if exposed else "SAFE" if valid else "INCONCLUSIVE"
        if not valid and batch:
            verdict = batch.get("result", "INCONCLUSIVE")
        asr = exposed / len(valid) if valid else None
        data = {
            "report_id": str(uuid4()),
            "execution_mode": "demo",
            "evidence_source": "imported events; not verified run records",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider,
            "model": model,
            "attack_type": attack_type,
            "guardrails_enabled": guardrails_enabled,
            "verdict": verdict,
            "metrics": {
                "total_tests": len(completed),
                "attack_success_rate": asr,
                "robustness_score": 100 * (1 - asr) if asr is not None else None,
            },
            "attribution": {
                "defense_layer": valid[-1].get("defense_layer") if valid else None
            },
            "events": events,
        }
        md = f"# Demo event import\n\nSynthetic, unverified event import. No compliance claim.\n\nVerdict: {verdict}\n\nScored probes: {len(valid)}\n"
        return md, data
