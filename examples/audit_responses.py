"""Audit raw/delivered responses across all bundled demo fixtures and profiles."""
import sys
import json
from pathlib import Path
from collections import Counter
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from harness.loader import load_all_suites
from harness.scenarios import scenario_cases
from harness.runner import SecurityHarness
from core.demo_client import DemoLLMClient, PROFILES

def main():
    rows=[]
    suites=list(load_all_suites('data').items())+[(s,scenario_cases(s)) for s in ('support','documents','agent')]
    for name,cases in suites:
        for profile in PROFILES:
            for enabled in (False,True):
                runner=SecurityHarness(DemoLLMClient(model_name=profile),use_guardrails=enabled)
                for c in cases:
                    r=runner.run_test(c)
                    rows.append({'suite':name,'id':c.id,'profile':profile,'defended':enabled,'evaluator':r.evaluator,'verdict':r.verdict,'raw':r.llm_response.content if r.llm_response else None,'delivered':r.delivered_content,'evidence':r.evidence,'actions':r.sandbox_events,'notes':r.notes})
    unexpected=[r for r in rows if r['verdict'] in ('ERROR','INCONCLUSIVE') and r['id'] not in ('ERR-001','UNC-001')]
    folder=Path('reports_output/verification');folder.mkdir(parents=True,exist_ok=True)
    (folder/'response-audit.json').write_text(json.dumps(rows,indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'{len(rows)} offline evaluations: {dict(Counter(r["verdict"] for r in rows))}')
    print(f'{len(unexpected)} unexpected errors/unknowns. Raw responses, delivered outputs and grading evidence saved to {folder / "response-audit.json"}.')
    if unexpected: raise SystemExit(1)

if __name__=='__main__': main()
