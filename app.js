let demo, current, mode='baseline';
let historyRequest=0;
const el=id=>document.getElementById(id);
const STAGES=['detection','investigation','escalation','response','closure'];
const TIMINGS={
  detection_to_investigation:'Detection → investigation',
  investigation_to_escalation:'Investigation → escalation',
  escalation_to_response:'Escalation → response',
  response_to_closure:'Response → closure',
  total_lifecycle:'Total lifecycle'
};
const DOMAIN_HELP={
  Detection:'Risk-weighted validated technique coverage',
  Response:'Containment SLA and lifecycle execution',
  Telemetry:'Weighted completeness and freshness',
  Quality:'Reviewed-alert precision and closure discipline',
  Governance:'Evidenced satisfied controls'
};

function add(tag,text='',cls=''){
  const node=document.createElement(tag);
  node.textContent=text;
  if(cls)node.className=cls;
  return node;
}

function present(value){return value!==undefined&&value!==null&&value!=='';}
function number(value,digits=1){return Number.isFinite(value)?value.toFixed(digits):'—';}
function minutes(value){return Number.isFinite(value)?number(value)+' min':'—';}
function title(value){return String(value).replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase());}

function evidence(value){
  if(!present(value))return null;
  const row=add('div','','evidence-ref');
  row.append(add('span','Evidence','meta-label'),add('code',String(value)));
  row.title='Evidence identifier — select text to copy';
  return row;
}

function badge(value,extra=''){
  const normalized=String(value||'unknown').toLowerCase().replaceAll('_','-').replace(/\s+/g,'-');
  return add('span',title(value||'unknown'),'badge '+normalized+(extra?' '+extra:''));
}

function renderDomains(report){
  const container=el('domains');
  container.replaceChildren();
  const domains=report.domains||{};
  for(const [name,value] of Object.entries(domains)){
    const row=add('div','','barrow');
    const label=add('div','','domain-label');
    label.append(add('span',name),add('small',DOMAIN_HELP[name]||'Assessment domain'));
    const track=add('div','','track');
    const bar=add('div','','bar');
    bar.style.width=Math.max(0,Math.min(100,value))+'%';
    track.append(bar);
    row.append(label,track,add('b',number(value)));
    container.append(row);
  }
}

function explanationCard(name,impact,finalScore){
  const card=add('article','','explain-card');
  const heading=add('div','','explain-heading');
  heading.append(add('strong',name),add('b',number(finalScore)));
  card.append(heading);
  const rows=[
    ['Legacy component',impact&&impact.legacy_score],
    ['Lifecycle component',impact&&impact.lifecycle_score],
    ['Lifecycle effect',impact&&impact.effect_points]
  ];
  for(const [label,value] of rows){
    if(!Number.isFinite(value))continue;
    const row=add('div','','explain-row');
    const shown=label==='Lifecycle effect'?(value>0?'+':'')+number(value)+' pts':number(value);
    row.append(add('span',label),add('b',shown));
    card.append(row);
  }
  return card;
}

function renderDomainExplanations(report){
  const container=el('domain-explanations');
  container.replaceChildren();
  const lifecycle=report.lifecycle||{};
  const scoring=lifecycle.scoring||{};
  const impact=scoring.domain_impact||{};
  const grid=add('div','','explain-grid');
  grid.append(
    explanationCard('Response',impact.Response,report.domains&&report.domains.Response),
    explanationCard('Quality',impact.Quality,report.domains&&report.domains.Quality)
  );
  container.append(grid);
  if(!(lifecycle.enabled&&scoring.applied)){
    container.append(add('p','Lifecycle evidence not provided. Response and Quality use their legacy evidence components.','empty-inline'));
  }

  const factors=el('confidence-factors');
  factors.replaceChildren();
  factors.append(add('span','Confidence factors','factor-title'));
  for(const [name,value] of Object.entries(report.confidence_factors||{})){
    const item=add('span','','factor');
    item.append(add('small',title(name)),add('b',number(value,3)));
    factors.append(item);
  }
}

function renderFindings(report){
  const container=el('findings');
  container.replaceChildren();
  const findings=Array.isArray(report.findings)?report.findings:[];
  const incidents=report.lifecycle&&Array.isArray(report.lifecycle.incidents)?report.lifecycle.incidents:[];
  const incidentIndexes=new Map(incidents.map((incident,index)=>[incident.incident_id,index]));
  el('finding-count').textContent=findings.length+' finding'+(findings.length===1?'':'s');
  if(!findings.length){
    container.append(add('p','No configured policy gaps found.','empty-state'));
    return;
  }
  for(const finding of findings){
    const card=add('article','','finding');
    const head=add('div','','finding-head');
    head.append(badge(finding.priority||'Unspecified','priority'),add('strong',finding.title||'Untitled finding'));
    card.append(head);
    if(present(finding.reason))card.append(add('p',finding.reason,'finding-reason'));
    const metadata=add('div','','metadata');
    const fields=[
      ['Owner',finding.owner],['Incident',finding.incident_id],['Alert',finding.alert_id],['Case',finding.case_id],
      ['Stage',finding.stage],['Type',finding.finding_type],
      ['Observed',Number.isFinite(finding.observed_minutes)?minutes(finding.observed_minutes):null],
      ['Threshold',Number.isFinite(finding.policy_threshold_minutes)?minutes(finding.policy_threshold_minutes):null]
    ];
    for(const [label,value] of fields){
      if(!present(value))continue;
      const item=add('span','','metadata-item');
      item.append(add('small',label),add('b',String(value)));
      metadata.append(item);
    }
    if(metadata.children.length)card.append(metadata);
    const ref=evidence(finding.evidence_ref);
    if(ref)card.append(ref);
    if(incidentIndexes.has(finding.incident_id)){
      const targetId='incident-'+(incidentIndexes.get(finding.incident_id)+1);
      const link=add('a','Open correlated incident →','finding-link');
      link.href='#'+targetId;
      link.onclick=()=>{
        const target=el(targetId);
        if(target)target.open=true;
      };
      card.append(link);
    }
    container.append(card);
  }
}

function summaryCard(label,value,note=''){
  const card=add('article','','summary-card');
  card.append(add('small',label),add('strong',String(value)));
  if(note)card.append(add('span',note));
  return card;
}

function renderComponentTable(components){
  const body=el('component-table');
  body.replaceChildren();
  for(const name of ['investigation','escalation','response','closure']){
    const component=components[name];
    if(!component)continue;
    const row=document.createElement('tr');
    const count=value=>Number.isFinite(value)?String(value):'—';
    const values=[title(name),number(component.score),count(component.applicable),count(component.timely),count(component.delayed),count(component.missing),count(component.unmeasured),count(component.not_applicable)];
    values.forEach((value,index)=>{
      const cell=add(index===0?'th':'td',String(value));
      if(index===0)cell.scope='row';
      row.append(cell);
    });
    body.append(row);
  }
}

function renderTimings(metrics){
  const container=el('timing-summary');
  container.replaceChildren();
  for(const [key,label] of Object.entries(TIMINGS)){
    const metric=metrics[key]||{};
    container.append(summaryCard(label,minutes(metric.average_minutes),Number.isFinite(metric.count)?metric.count+' measured':'No measurements'));
  }
}

function stageCard(stageName,stage,evaluation){
  const card=add('article','','stage-card');
  const head=add('div','','stage-head');
  const result=evaluation&&evaluation.result?evaluation.result:(stage?'recorded':'missing');
  head.append(add('strong',title(stageName)),badge(result));
  card.append(head);
  if(!stage){
    card.append(add('p',result==='not_required'?'This stage was not required.':'No stage was recorded.','empty-inline'));
  }
  const facts=add('dl','','stage-facts');
  const entries=stage?[['Timestamp',stage.timestamp],['Status',stage.status]]:[];
  if(evaluation){
    entries.push(['Observed delay',Number.isFinite(evaluation.observed_minutes)?minutes(evaluation.observed_minutes):null]);
    entries.push(['Policy target',Number.isFinite(evaluation.threshold_minutes)?minutes(evaluation.threshold_minutes):null]);
    entries.push(['Earned credit',Number.isFinite(evaluation.credit)?number(evaluation.credit):null]);
  }
  for(const [label,value] of entries){
    if(!present(value))continue;
    facts.append(add('dt',label),add('dd',String(value)));
  }
  if(facts.children.length)card.append(facts);
  const ref=stage&&evidence(stage.evidence_ref);
  if(ref)card.append(ref);
  return card;
}

function incidentPanel(incident,index){
  const details=add('details','','incident');
  details.id='incident-'+(index+1);
  const summary=document.createElement('summary');
  const identity=add('span','','incident-identity');
  identity.append(add('strong',incident.incident_id||'Unknown incident'),add('small',(incident.alert_id||'No alert')+' · '+(incident.case_id||'No case')+' · '+(incident.source_id||'No source')));
  const summaryMetrics=add('span','','incident-summary-metrics');
  summaryMetrics.append(badge(incident.complete?'complete':'incomplete'));
  if(incident.timing_minutes){
    summaryMetrics.append(add('span','D→I '+minutes(incident.timing_minutes.detection_to_investigation),'timing-chip'));
    summaryMetrics.append(add('span','R→C '+minutes(incident.timing_minutes.response_to_closure),'timing-chip'));
    summaryMetrics.append(add('span','Total '+minutes(incident.timing_minutes.total_lifecycle),'timing-chip'));
  }
  summary.append(identity,summaryMetrics);
  details.append(summary);

  const meta=add('div','','incident-meta');
  meta.append(
    summaryCard('Incident',incident.incident_id||'—'),
    summaryCard('Alert',incident.alert_id||'—'),
    summaryCard('Case',incident.case_id||'—'),
    summaryCard('Source',incident.source_id||'—'),
    summaryCard('Escalation required',incident.escalation_required?'Yes':'No'),
    summaryCard('Lifecycle',incident.complete?'Complete':'Incomplete')
  );
  details.append(meta);

  const timing=add('div','','incident-timings');
  for(const [key,label] of Object.entries(TIMINGS)){
    timing.append(summaryCard(label,minutes(incident.timing_minutes&&incident.timing_minutes[key])));
  }
  details.append(timing);

  const stages=add('div','','stages');
  for(const name of STAGES){
    const stage=incident.stages&&incident.stages[name];
    const evaluation=incident.stage_evaluation&&incident.stage_evaluation[name];
    stages.append(stageCard(name,stage,evaluation));
  }
  details.append(stages);
  return details;
}

function traceLine(items){
  const line=add('div','','trace-line');
  items.forEach((item,index)=>{
    if(index)line.append(add('span','→','trace-arrow'));
    const node=add('span','','trace-node');
    node.append(add('small',item[0]),add('b',String(item[1])));
    line.append(node);
  });
  return line;
}

function renderLifecycle(report){
  const lifecycle=report.lifecycle||{};
  const incidents=Array.isArray(lifecycle.incidents)?lifecycle.incidents:[];
  const enabled=lifecycle.enabled===true;
  const content=el('lifecycle-content');
  const unavailable=el('lifecycle-unavailable');
  el('lifecycle-state').textContent=enabled?incidents.length+' correlated':'Legacy assessment';
  if(!enabled){
    content.hidden=true;
    unavailable.hidden=false;
    unavailable.textContent='Lifecycle evidence not provided. This assessment uses the legacy source, technique, case, and control evidence model.';
    return;
  }
  if(!incidents.length){
    content.hidden=true;
    unavailable.hidden=false;
    unavailable.textContent='Lifecycle mode is enabled, but no correlated incidents were supplied.';
    return;
  }
  content.hidden=false;
  unavailable.hidden=true;

  const scoring=lifecycle.scoring||{};
  const components=scoring.components||{};
  const operational=scoring.operational_response||{};
  const closure=scoring.closure_discipline||{};
  const incomplete=Math.max(0,(lifecycle.incident_count||0)-(lifecycle.complete_incidents||0));
  const lifecycleFindings=(Array.isArray(report.findings)?report.findings:[]).filter(f=>present(f.incident_id)).length;

  const trace=el('score-trace');
  trace.replaceChildren();
  trace.append(add('p','Score-to-evidence trace','trace-title'));
  trace.append(traceLine([
    ['Overall',number(report.score)],['Response',number(report.domains&&report.domains.Response)],
    ['Operational response',number(operational.score)],['Incidents',lifecycle.incident_count||0]
  ]));
  trace.append(traceLine([
    ['Overall',number(report.score)],['Quality',number(report.domains&&report.domains.Quality)],
    ['Closure discipline',number(closure.score)],['Lifecycle findings',lifecycleFindings]
  ]));

  const summary=el('lifecycle-summary');
  summary.replaceChildren();
  summary.append(
    summaryCard('Correlated incidents',lifecycle.incident_count||0),
    summaryCard('Complete',lifecycle.complete_incidents||0),
    summaryCard('Incomplete',incomplete),
    summaryCard('Operational response',number(operational.score)),
    summaryCard('Closure discipline',number(closure.score))
  );
  renderComponentTable(components);
  renderTimings(lifecycle.timing_metrics||{});

  const incidentList=el('incidents');
  incidentList.replaceChildren();
  incidents.forEach((incident,index)=>incidentList.append(incidentPanel(incident,index)));
}

function signed(value,suffix=''){
  if(!Number.isFinite(value))return '—';
  return (value>0?'+':'')+number(value)+suffix;
}

function displayTime(value){
  const parsed=new Date(value);
  if(Number.isNaN(parsed.getTime()))return value||'—';
  return parsed.toISOString().slice(0,16).replace('T',' ')+' UTC';
}

function svgNode(name,attributes={},textValue=''){
  const node=document.createElementNS('http://www.w3.org/2000/svg',name);
  for(const [key,value] of Object.entries(attributes))node.setAttribute(key,String(value));
  if(textValue)node.textContent=textValue;
  return node;
}

function renderTrendChart(points){
  const container=el('trend-chart');
  container.replaceChildren();
  if(!points.length){
    container.append(add('p','No compatible historical observations are available.','empty-inline'));
    return;
  }
  const width=900,height=230,left=48,right=24,top=20,bottom=48;
  const chartWidth=width-left-right,chartHeight=height-top-bottom;
  const x=index=>points.length===1?left+chartWidth/2:left+(chartWidth*index/(points.length-1));
  const y=value=>top+chartHeight-(Math.max(0,Math.min(100,value))*chartHeight/100);
  const svg=svgNode('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'Overall assessment score by assessment date'});
  for(const mark of [0,25,50,75,100]){
    const position=y(mark);
    svg.append(svgNode('line',{x1:left,y1:position,x2:width-right,y2:position,class:'trend-grid'}));
    svg.append(svgNode('text',{x:left-9,y:position+4,class:'trend-axis','text-anchor':'end'},String(mark)));
  }
  const coordinates=points.map((point,index)=>`${x(index)},${y(point.score)}`).join(' ');
  if(points.length>1)svg.append(svgNode('polyline',{points:coordinates,class:'trend-line'}));
  points.forEach((point,index)=>{
    const horizontal=x(index),vertical=y(point.score);
    const group=svgNode('g',{class:'trend-point'});
    group.append(svgNode('circle',{cx:horizontal,cy:vertical,r:5}));
    group.append(svgNode('text',{x:horizontal,y:vertical-11,'text-anchor':'middle',class:'trend-value'},number(point.score)));
    group.append(svgNode('text',{x:horizontal,y:height-20,'text-anchor':'middle',class:'trend-date'},String(point.assessed_at||'').slice(0,10)));
    group.append(svgNode('title',{},`${displayTime(point.assessed_at)} · score ${number(point.score)}`));
    svg.append(group);
  });
  container.append(svg);
}

function deltaGrid(delta){
  const container=add('div','','delta-grid');
  const entries=[['Overall',delta&&delta.score],['Confidence',delta&&delta.confidence]];
  for(const name of ['Detection','Response','Telemetry','Quality','Governance']){
    entries.push([name,delta&&delta.domains&&delta.domains[name]]);
  }
  entries.forEach(([label,value])=>{
    const card=summaryCard(label,signed(value,' pts'));
    if(Number.isFinite(value))card.classList.add(value>0?'positive':value<0?'negative':'neutral');
    container.append(card);
  });
  return container;
}

function renderHistorySummary(history){
  const summary=history.summary;
  const container=el('history-summary');
  const latest=el('history-latest-delta');
  container.replaceChildren();
  latest.replaceChildren();
  if(!summary){
    latest.append(add('p','A second compatible assessment is required for change metrics.','empty-inline'));
    return;
  }
  container.append(
    summaryCard('Current score',number(summary.current)),
    summaryCard('Previous delta',signed(summary.previous_delta&&summary.previous_delta.score,' pts')),
    summaryCard('Best score',number(summary.best&&summary.best.score)),
    summaryCard('Worst score',number(summary.worst&&summary.worst.score)),
    summaryCard('Direction',title(summary.direction),summary.streak?summary.streak+' consecutive change'+(summary.streak===1?'':'s'):'')
  );
  latest.append(add('p','Latest compatible change','trace-title'));
  if(summary.previous_delta)latest.append(deltaGrid(summary.previous_delta));
  else latest.append(add('p','A second compatible assessment is required for change metrics.','empty-inline'));
}

function historyOption(record){
  const option=document.createElement('option');
  option.value=record.assessment_id;
  option.textContent=String(record.assessed_at||'').slice(0,10)+' · '+number(record.score)+' · '+record.maturity;
  return option;
}

function renderHistorySelections(points){
  const before=el('history-before'),after=el('history-after'),button=el('history-compare');
  before.replaceChildren();
  after.replaceChildren();
  points.forEach(point=>{
    before.append(historyOption(point));
    after.append(historyOption(point));
  });
  const enabled=points.length>=2;
  before.disabled=!enabled;
  after.disabled=!enabled;
  button.disabled=!enabled;
  if(enabled){
    before.value=points[points.length-2].assessment_id;
    after.value=points[points.length-1].assessment_id;
  }
  const comparison=el('history-comparison');
  comparison.replaceChildren();
  if(!enabled)comparison.append(add('p','At least two compatible assessments are required for comparison.','empty-inline'));
}

function renderHistoryTable(records,trendPoints){
  const body=el('history-table');
  body.replaceChildren();
  const compatible=new Set(trendPoints.map(point=>point.assessment_id));
  const driftById=new Map(trendPoints.map(point=>[point.assessment_id,point.drift]));
  for(const record of records){
    const row=document.createElement('tr');
    const run=document.createElement('th');
    run.scope='row';
    run.append(add('code',record.assessment_id));
    row.append(run);
    const values=[displayTime(record.assessed_at),displayTime(record.evidence_as_of),record.policy_version,number(record.score),number(record.confidence)+'%',record.maturity,record.lifecycle_enabled?'Enabled':'Legacy'];
    values.forEach(value=>row.append(add('td',String(value))));
    const drift=driftById.get(record.assessment_id);
    const driftCell=document.createElement('td');
    driftCell.append(compatible.has(record.assessment_id)?badge(drift&&drift.detected?'drift':'clear'):badge('incompatible'));
    row.append(driftCell);
    const action=document.createElement('td');
    const button=add('button','View','table-action');
    button.type='button';
    button.onclick=()=>openHistoricalAssessment(record.assessment_id);
    action.append(button);
    row.append(action);
    body.append(row);
  }
}

function renderHistoryComparison(result){
  const container=el('history-comparison');
  container.replaceChildren();
  const heading=add('div','','comparison-heading');
  heading.append(add('strong','Comparison result'),badge(result.drift_detected?'drift detected':'no drift'));
  container.append(heading);
  container.append(deltaGrid({score:result.score_delta,confidence:result.confidence_delta,domains:result.domain_delta}));
  const drift=result.drift||{};
  if(Array.isArray(drift.reasons)&&drift.reasons.length){
    const list=add('ul','','drift-reasons');
    drift.reasons.forEach(reason=>list.append(add('li',reason)));
    container.append(list);
  }else{
    container.append(add('p','No configured historical drift rule was triggered.','empty-inline'));
  }
}

async function fetchJson(url){
  const response=await fetch(url);
  const body=await response.json();
  if(!response.ok)throw Error(body.error||'History request failed');
  return body;
}

async function runHistoryComparison(){
  const before=el('history-before').value,after=el('history-after').value;
  const container=el('history-comparison');
  if(!before||!after)return;
  if(before===after){
    container.replaceChildren(add('p','Choose two different assessments.','empty-inline'));
    return;
  }
  container.replaceChildren(add('p','Comparing assessments…','empty-inline'));
  try{
    const result=await fetchJson('/api/history/compare?before='+encodeURIComponent(before)+'&after='+encodeURIComponent(after));
    renderHistoryComparison(result);
  }catch(error){
    container.replaceChildren(add('p',error.message,'history-error'));
  }
}

async function openHistoricalAssessment(assessmentId){
  try{
    const stored=await fetchJson('/api/history/'+encodeURIComponent(assessmentId));
    mode='history';
    render(stored.report);
    window.scrollTo({top:0});
    el('status').textContent='Viewing historical assessment '+assessmentId+' · '+displayTime(stored.assessment.assessed_at);
  }catch(error){
    el('status').textContent=error.message;
  }
}

async function loadHistory(scope){
  const request=++historyRequest;
  const content=el('history-content'),unavailable=el('history-unavailable');
  content.hidden=true;
  unavailable.hidden=false;
  unavailable.textContent='Loading persisted assessments…';
  el('history-state').textContent='Loading history';
  if(!scope){
    unavailable.textContent='No scope is available for historical lookup.';
    return;
  }
  try{
    const encoded=encodeURIComponent(scope);
    const [listing,history]=await Promise.all([
      fetchJson('/api/history?scope='+encoded),
      fetchJson('/api/history/trend?scope='+encoded)
    ]);
    if(request!==historyRequest)return;
    const records=Array.isArray(listing.assessments)?listing.assessments:[];
    const points=Array.isArray(history.points)?history.points:[];
    if(!records.length){
      unavailable.textContent='No persisted assessments are available for this scope.';
      el('history-state').textContent='No history';
      return;
    }
    unavailable.hidden=true;
    content.hidden=false;
    el('history-state').textContent=records.length+' assessment'+(records.length===1?'':'s');
    renderHistorySummary(history);
    renderTrendChart(points);
    renderHistorySelections(points);
    renderHistoryTable(records,points);
    if(history.excluded_incompatible){
      el('history-state').textContent+=` · ${history.excluded_incompatible} incompatible`;
    }
  }catch(error){
    if(request!==historyRequest)return;
    el('history-state').textContent='History unavailable';
    unavailable.textContent=error.message;
  }
}

function renderPolicy(report){
  const policy=report.policy||{};
  el('policy-version').textContent='Active policy: '+(policy.id||'Not reported');
  const container=el('policy-thresholds');
  container.replaceChildren();
  const lifecycleEnabled=report.lifecycle&&report.lifecycle.enabled;
  const lifecyclePolicy=policy.lifecycle;
  if(!lifecycleEnabled||!lifecyclePolicy){
    container.append(add('p','Lifecycle thresholds are not applied to this legacy assessment.','empty-inline'));
    return;
  }
  container.append(add('p','Prototype supervisory lifecycle thresholds','policy-label'));
  const grid=add('div','','threshold-grid');
  const thresholds=[
    ['Investigation',lifecyclePolicy.investigation_target_minutes],
    ['Escalation',lifecyclePolicy.escalation_target_minutes],
    ['Response',lifecyclePolicy.response_target_minutes],
    ['Closure',lifecyclePolicy.closure_target_minutes]
  ];
  thresholds.forEach(([label,value])=>grid.append(summaryCard(label,Number.isFinite(value)?value+' min':'—')));
  container.append(grid);
}

function render(report){
  current=report;
  el('score').textContent=number(report.score);
  el('confidence').textContent=number(report.confidence)+'%';
  el('maturity').textContent=report.maturity||'—';
  el('gate').textContent=report.maturity==='Provisional'?'Evidence gate failed':'Policy gates satisfied';
  const counts=report.counts||{};
  el('count').textContent=(counts.techniques??0)+' / '+(counts.cases??0);
  el('countsub').textContent='Techniques / incident cases';
  el('status').textContent=(report.synthetic?'Synthetic dataset. ':'Imported dataset. ')+(report.scope||'Unspecified scope')+' · '+(report.as_of||'No assessment time');
  renderDomains(report);
  renderDomainExplanations(report);
  renderFindings(report);
  renderLifecycle(report);
  renderPolicy(report);
  loadHistory(report.scope);
  el('scope').textContent=(report.policy&&report.policy.id?report.policy.id:'Unversioned policy')+' · '+(counts.sources??0)+' declared sources · '+(counts.reviewed_cases??0)+' reviewed cases';
  el('hash').textContent=report.sha256?'SHA-256 '+report.sha256:'Input digest not reported';
  if(mode==='degraded'&&demo&&demo.comparison){
    el('delta').textContent='Scenario change: '+number(demo.comparison.score_delta)+' points · '+(demo.comparison.drift_alert?'Drift alert active.':'No drift alert.');
  }else{
    el('delta').textContent='Traceable inputs and deterministic policy. A score is not a certification.';
  }
}

async function init(){
  try{
    const response=await fetch('/api/demo');
    if(!response.ok)throw Error('Demo loading failed');
    demo=await response.json();
    render(demo.baseline);
  }catch(error){
    el('status').textContent=error.message;
  }
}

el('baseline').onclick=()=>{if(demo){mode='baseline';render(demo.baseline);}};
el('degraded').onclick=()=>{if(demo){mode='degraded';render(demo.degraded);}};
el('upload').onchange=async event=>{
  const file=event.target.files[0];
  if(!file)return;
  try{
    if(file.size>2000000)throw Error('Upload limit is 2 MB');
    const text=await file.text();
    const response=await fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},body:text});
    const report=await response.json();
    if(!response.ok)throw Error(report.error);
    mode='import';
    render(report);
  }catch(error){
    el('status').textContent=error.message;
  }
};
el('download').onclick=()=>{
  if(!current)return;
  const link=document.createElement('a');
  const url=URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:'application/json'}));
  link.href=url;
  link.download='sat-sa-assessment.json';
  link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
};
el('history-compare').onclick=runHistoryComparison;

init();
