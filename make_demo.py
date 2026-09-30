"""Recreate the two explicitly synthetic fixtures."""
from pathlib import Path
from datetime import datetime, timezone, timedelta
import copy
import json
from engine import assess, compare
ROOT=Path(__file__).parent
now=datetime(2026,9,30,12,tzinfo=timezone.utc)
iso=lambda dt:dt.isoformat()
source_ids=['siem-1','edr-1','soar-1','ueba-1','cti-1']
data={'scope':'Synthetic SOC A / scope-v1','as_of':iso(now),'synthetic':True,'sources':[],'techniques':[],'cases':[],'controls':[]}
for i,kind in enumerate(['SIEM','EDR','SOAR','UEBA','CTI']):
    data['sources'].append({'id':source_ids[i],'kind':kind,'weight':[5,5,4,3,3][i],'completeness':1.0,'last_seen':iso(now-timedelta(hours=2)),'evidence_ref':'demo://telemetry/'+kind.lower()})
ids=['T1059','T1078','T1003','T1021','T1053','T1105','T1566','T1486','T1110','T1041','T1070','T1087']
weights=[5,5,4,4,3,3,2,2,4,3,3,2]
for i,tid in enumerate(ids):
    data['techniques'].append({'id':tid,'source_id':source_ids[i%5],'risk_weight':weights[i],'status':'passed' if i<8 else 'failed' if i<10 else 'untested','tested_at':iso(now-timedelta(days=3)) if i<10 else None,'evidence_ref':'demo://validation/'+tid})
for i in range(24):
    detected=now-timedelta(days=2,hours=i)
    data['cases'].append({'id':f'CASE-{i+1:03}','detected_at':iso(detected),'contained_at':iso(detected+timedelta(minutes=30 if i<15 else 150)),'sla_minutes':60,'disposition':'true_positive' if i<20 else 'false_positive','evidence_ref':f'demo://case/{i+1:03}'})
for i,name in enumerate(['access-review','playbook-approval','retention-policy','incident-review','recovery-drill']):
    data['controls'].append({'id':name,'satisfied':i<4,'critical':i<2,'evidence_ref':'demo://controls/'+name})
data['lifecycles']=[]
for i in range(6):
    detected=now-timedelta(days=2,hours=i)
    incident_id=f'INC-{i+1:03}'
    stage=lambda name,minutes,status:{'timestamp':iso(detected+timedelta(minutes=minutes)),'evidence_ref':f'demo://lifecycle/{incident_id}/{name}','status':status}
    escalation_required=i%2==0
    data['lifecycles'].append({
        'incident_id':incident_id,
        'alert_id':f'ALERT-{i+1:03}',
        'case_id':f'CASE-{i+1:03}',
        'source_id':source_ids[i%5],
        'escalation_required':escalation_required,
        'detection':stage('detection',0,'detected'),
        'investigation':stage('investigation',5,'completed'),
        'escalation':stage('escalation',10,'completed') if escalation_required else None,
        'response':stage('response',30,'contained'),
        'closure':stage('closure',90,'closed'),
    })
degraded=copy.deepcopy(data)
degraded['sources'][1]['last_seen']=iso(now-timedelta(hours=100))
degraded['sources'][1]['completeness']=0
degraded['sources'][3]['last_seen']=iso(now-timedelta(hours=60))
degraded['sources'][3]['completeness']=.6
degraded['techniques'][1]['status']='failed'
degraded['techniques'][3]['status']='failed'
first_detection=datetime.fromisoformat(degraded['lifecycles'][0]['detection']['timestamp'])
degraded['lifecycles'][0]['investigation']['timestamp']=iso(first_detection+timedelta(minutes=25))
degraded['lifecycles'][0]['escalation']['timestamp']=iso(first_detection+timedelta(minutes=27))
degraded['lifecycles'][0]['closure']['timestamp']=iso(first_detection+timedelta(minutes=300))
second_detection=datetime.fromisoformat(degraded['lifecycles'][1]['detection']['timestamp'])
degraded['cases'][1]['sla_minutes']=90
degraded['cases'][1]['contained_at']=iso(second_detection+timedelta(minutes=75))
degraded['lifecycles'][1]['response']['timestamp']=iso(second_detection+timedelta(minutes=75))
degraded['lifecycles'][2]['escalation']=None
degraded['lifecycles'][3]['closure']=None
fifth_detection=datetime.fromisoformat(degraded['lifecycles'][4]['detection']['timestamp'])
degraded['lifecycles'][4]['escalation']['timestamp']=iso(fifth_detection+timedelta(minutes=25))
degraded['lifecycles'][4]['response']=None
degraded['lifecycles'][5]['investigation']=None
(ROOT/'data').mkdir(exist_ok=True)
for name,obj in [('baseline',data),('degraded',degraded)]:
    (ROOT/'data'/f'{name}.json').write_text(json.dumps(obj,indent=2))
a,b=assess(data),assess(degraded)
(ROOT/'data'/'demo-results.json').write_text(json.dumps({'baseline':a,'degraded':b,'comparison':compare(a,b)},indent=2))
print(json.dumps({'baseline':{k:a[k] for k in ['score','confidence','maturity','domains','counts']},'degraded':{k:b[k] for k in ['score','confidence','maturity']},'comparison':compare(a,b)},indent=2))
