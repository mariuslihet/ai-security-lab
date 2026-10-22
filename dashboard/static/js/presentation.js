/* Shared presentation logic: security rates belong to one policy; coverage to the run. */
(function(root){
  function summarize(run, requested){
    const named=Object.keys(run.config.named_policies||{});
    const policies=named.length?['baseline',...named]:run.config.compare?['baseline','defended']:[run.config.guardrails?'defended':'baseline'];
    const preferred=named.includes('full')?'full':named[0]|| (policies.includes('defended')?'defended':'baseline');
    const selected=policies.includes(requested)?requested:preferred;
    const results=Object.values(run.arms).flatMap(a=>a.results||[]);
    const errors=Object.values(run.arms).reduce((n,a)=>n+(a.metrics.errors||0),0);
    const unknowns=Object.values(run.arms).reduce((n,a)=>n+(a.metrics.inconclusive||0),0);
    const regressions=results.filter(r=>r.expectation_met===false).length;
    const reasons=[];
    if(regressions)reasons.push(`${regressions} outcome${regressions===1?'':'s'} did not meet the expected security contract.`);
    if(errors||unknowns)reasons.push(`${errors} errors and ${unknowns} inconclusive outcomes require review; these are excluded from ASR.`);
    const warning=run.error|| (run.status==='needs_review'?(reasons.join(' ')||'Review the recorded evidence for this saved run.'):null);
    return {selected,policies,arm:run.arms[selected],errors,unknowns,regressions,warning};
  }
  if(typeof module!=='undefined'&&module.exports)module.exports={summarize};
  else root.LabPresentation={summarize};
})(typeof window==='undefined'?globalThis:window);
