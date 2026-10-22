"""Exercise the same summary module used by the browser, without duplicating its logic."""
import shutil
import subprocess
from pathlib import Path
import pytest


def test_policy_scope_and_review_reasons():
    node=shutil.which('node')
    if not node: pytest.skip('Node is required for dashboard JavaScript unit checks')
    script=r'''
const assert=require('node:assert/strict');
const {summarize}=require('./dashboard/static/js/presentation.js');
const arm=(verdicts,errors=0,inconclusive=0)=>({metrics:{errors,inconclusive},results:verdicts.map(v=>({expectation_met:v}))});
const run={config:{named_policies:{full:{},observe_only:{}}},status:'needs_review',completed:12,planned:12,arms:{baseline:arm([true,true,true,true]),full:arm([true,true,true,true]),observe_only:arm([true,false,false,true])}};
let v=summarize(run);
assert.equal(v.selected,'full');assert.equal(v.arm,run.arms.full);
assert.equal(v.regressions,2);assert.equal(v.errors,0);
assert.equal(v.warning,'2 outcomes did not meet the expected security contract.');
assert.equal(summarize(run,'observe_only').arm,run.arms.observe_only);
run.arms.full=arm([],1,1);v=summarize(run);
assert.match(v.warning,/2 outcomes/);assert.match(v.warning,/1 errors and 1 inconclusive/);
run.status='running';assert.equal(summarize(run).warning,null);
run.arms={baseline:arm([true])};v=summarize(run);
assert.equal(v.selected,'full');assert.equal(v.arm,undefined); // no baseline fallback before full starts
run.config={named_policies:{canary_only:{},full:{}}};assert.equal(summarize(run).selected,'full');
run.config={compare:true};assert.equal(summarize(run).selected,'defended');
run.config={guardrails:false};assert.equal(summarize(run).selected,'baseline');
run.status='needs_review';assert.match(summarize(run).warning,/saved run/);
run.error='Budget exceeded';assert.equal(summarize(run).warning,'Budget exceeded');
'''
    result=subprocess.run([node,'-e',script],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
