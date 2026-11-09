from __future__ import annotations
import math
from typing import Any

def analyze(rows:list[dict[str,Any]], contamination:float=.03)->dict[str,Any]:
    numeric=[]
    for row in rows:
        if not isinstance(row,dict):continue
        item={}
        for k,v in row.items():
            key=str(k).lower()
            if key.startswith('_') or key in {'sample_index','record_index','index','timestamp','timestamp_us','timestamp_ms','time','time_ms','time_us'}: continue
            try:
                x=float(v)
                if math.isfinite(x):item[str(k)]=x
            except (TypeError,ValueError):pass
        if item:numeric.append(item)
    if len(numeric)<12:return {'method':'insufficient-data','alerts':[],'sample_count':len(numeric),'limitations':['At least 12 numeric samples are required for this initial anomaly screen.']}
    counts={}
    for row in numeric:
        for key in row: counts[key]=counts.get(key,0)+1
    keys=sorted(k for k,n in counts.items() if n>=12)
    if not keys:return {'method':'insufficient-data','alerts':[],'sample_count':len(numeric),'limitations':['No sufficiently populated numeric channels were found.']}
    # Robust univariate screening is deterministic and does not train on external datasets.
    alerts=[]; stats={}
    for key in keys[:128]:
        vals=[r[key] for r in numeric if key in r]
        med=sorted(vals)[len(vals)//2]; dev=sorted(abs(x-med) for x in vals); mad=dev[len(dev)//2]
        scale=max(1.4826*mad,1e-12); out=[(i,r[key]) for i,r in enumerate(numeric) if key in r and abs(r[key]-med)/scale>6.0]
        stats[key]={'median':med,'robust_scale':scale,'outlier_count':len(out)}
        for i,v in out[:100]: alerts.append({'channel':key,'sample_index':i,'value':v,'robust_z':round(abs(v-med)/scale,2),'classification':'statistical-outlier-candidate','confidence':'screening-only'})
    method='robust-median-absolute-deviation'
    ml={'available':False,'status':'not-run'}
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        matrix=[]
        usable=[k for k in keys if all(k in r for r in numeric)]
        if len(usable)>=2 and len(numeric)>=30:
            X=np.asarray([[r[k] for k in usable] for r in numeric],dtype=float)
            if np.isfinite(X).all():
                model=IsolationForest(n_estimators=100,contamination=min(max(contamination,.001),.25),random_state=41,n_jobs=1)
                pred=model.fit_predict(X); scores=model.decision_function(X)
                inds=[i for i,p in enumerate(pred) if p<0]
                ml={'available':True,'status':'completed','algorithm':'IsolationForest','features':usable,'outlier_indices':inds[:500],'score_preview':[round(float(x),6) for x in scores[:500]],'warning':'Unsupervised anomaly candidates only; not evidence of malfunction, attack, or intent.'}
                method+=' + IsolationForest'
    except Exception as exc: ml={'available':False,'status':'unavailable','reason':type(exc).__name__}
    return {'method':method,'sample_count':len(numeric),'features':keys[:128],'statistics':stats,'alerts':alerts[:500],'ml':ml,'limitations':['No labeled ground truth or vehicle-specific baseline was supplied.','Outliers are hypotheses for investigator review, not confirmed faults or malicious activity.','Do not compare different airframes or incompatible units without normalization.']}
