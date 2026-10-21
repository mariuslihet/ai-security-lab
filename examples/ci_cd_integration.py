"""Offline correctness gate. This is NOT a live-model security certification."""

import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from harness.service import RunService, RunStore, RunRequest


def main():
    with tempfile.TemporaryDirectory() as directory:
        service = RunService(RunStore(Path(directory) / "runs.sqlite3"))
        try:
            identifier = service.start(
                RunRequest(suite="all", compare=True), background=False
            )
            run = service.store.get(identifier)
            assert run["completed"] == run["planned"] and run["completed"] > 0
            assert (
                run["status"] == "needs_review"
            ), "Fault and ambiguous fixtures must remain visible"
            assert run["execution_mode"] == "demo"
            base, defended = (
                run["arms"][key]["metrics"] for key in ("baseline", "defended")
            )
            assert base["attack_success_rate"] is not None
            assert defended["attack_success_rate"] <= base["attack_success_rate"]
            assert defended["false_positive_rate"] is not None
            assert base["errors"] == defended["errors"] == 1
            print(
                "DEMO REGRESSION PASSED: execution, error visibility, paired comparison and benign controls verified."
            )
            print("No live-model security assessment was performed.")
        finally:
            service.close()


if __name__ == "__main__":
    main()
