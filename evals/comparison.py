"""Evidence-preserving comparison; mismatched conditions are never causal proof."""

from collections import defaultdict


def compare_runs(before, after):
    warnings = []
    for key in ("dataset_sha256", "engine_version", "evaluator_version"):
        if before.get(key) != after.get(key):
            warnings.append(f"Different {key}")
    for key in ("profile", "seed", "provider", "scenario", "repetitions"):
        if before["config"].get(key) != after["config"].get(key):
            warnings.append(f"Different {key}")
    if any(r["status"] not in ("completed", "needs_review") for r in (before, after)):
        warnings.append("At least one run is incomplete")

    def index(run):
        found = {}
        for arm, summary in run["arms"].items():
            counts = defaultdict(int)
            for result in summary["results"]:
                identifier = result["test_case"]["id"]
                counts[identifier] += 1
                found[(arm, identifier, counts[identifier])] = result
        return found

    left, right = index(before), index(after)
    rows = []
    for key in sorted(left.keys() | right.keys()):
        old, new = left.get(key), right.get(key)
        a, b = old["verdict"] if old else None, new["verdict"] if new else None
        if old is None:
            change = "added"
        elif new is None:
            change = "missing"
        elif a == b:
            change = "unchanged"
        elif b in ("ERROR", "INCONCLUSIVE"):
            change = "lost evidence"
        elif a in ("ERROR", "INCONCLUSIVE"):
            change = "evidence restored"
        elif b == "EXPOSED":
            change = "new exposure"
        elif a == "EXPOSED":
            change = "resolved exposure"
        elif b == "FALSE_POSITIVE":
            change = "new false positive"
        elif a == "FALSE_POSITIVE":
            change = "resolved false positive"
        else:
            change = "changed"
        rows.append(
            dict(
                arm=key[0],
                case_id=key[1],
                repetition=key[2],
                before=a,
                after=b,
                change=change,
            )
        )
    if left.keys() != right.keys():
        warnings.append("Different coverage or arms")
    deltas = {}
    for arm in before["arms"].keys() & after["arms"].keys():
        deltas[arm] = {}
        for metric in ("attack_success_rate", "false_positive_rate"):
            a, b = before["arms"][arm]["metrics"].get(metric), after["arms"][arm][
                "metrics"
            ].get(metric)
            deltas[arm][metric] = None if a is None or b is None else b - a
    return dict(
        before=before["id"],
        after=after["id"],
        comparable=not warnings,
        warnings=warnings,
        metric_deltas=deltas,
        probes=rows,
    )
