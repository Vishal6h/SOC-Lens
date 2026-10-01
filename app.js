const PAGES=['dashboard','assessments','incidents','findings','history','reports','policy','settings'];
const PAGE_TITLES={dashboard:'Dashboard',assessments:'Assessments',incidents:'Incidents',findings:'Findings',history:'History',reports:'Reports',policy:'Policy',settings:'Settings'};
const STAGES=['detection','investigation','escalation','response','closure'];
const TIMINGS={
  detection_to_investigation:'Detection to investigation',
  investigation_to_escalation:'Investigation to escalation',
  escalation_to_response:'Escalation to response',
  response_to_closure:'Response to closure',
  total_lifecycle:'Total process time'
};
const DOMAIN_HELP={
  Detection:'Validated detection coverage',
  Response:'Containment and incident execution',
  Telemetry:'Source completeness and freshness',
  Quality:'Reviewed cases and closure discipline',
  Governance:'Controls supported by evidence'
};

let demo=null;
let current=null;
let currentAssessmentId=null;
let currentManifest=null;
let mode='baseline';
let serviceState=null;
let importProfiles=[];
let stagedImports=[];
let buildReady=false;
let preparationSession=null;
let historyState=null;
let historyRequest=0;
let renderedPages=new Set();
const historyCache=new Map();
const storedCache=new Map();

const el=id=>document.getElementById(id);

function add(tag,text='',className=''){
  const node=document.createElement(tag);
  node.textContent=text;
  if(className)node.className=className;
  return node;
}

function present(value){return value!==undefined&&value!==null&&value!=='';}
function number(value,digits=1){return Number.isFinite(value)?value.toFixed(digits):'—';}
function minutes(value){return Number.isFinite(value)?number(value)+' min':'Not measured';}
function title(value){return String(value||'').replaceAll('_',' ').replaceAll('-',' ').replace(/\b\w/g,character=>character.toUpperCase());}
function signed(value,suffix=''){return Number.isFinite(value)?(value>0?'+':'')+number(value)+suffix:'—';}

function displayTime(value){
  const parsed=new Date(value);
  if(Number.isNaN(parsed.getTime()))return value||'Not available';
  return parsed.toISOString().slice(0,16).replace('T',' ')+' UTC';
}

function badge(value,extra=''){
  const normalized=String(value||'not evaluated').toLowerCase().replaceAll('_','-').replace(/\s+/g,'-');
  return add('span',title(value||'not evaluated'),'badge '+normalized+(extra?' '+extra:''));
}

function detailItem(label,value,note=''){
  const item=add('div','','detail-item');
  item.append(add('small',label),add('strong',present(value)?String(value):'Not available'));
  if(note)item.append(add('span',note));
  return item;
}

function summaryCard(label,value,note=''){
  const card=add('article','','summary-card');
  card.append(add('small',label),add('strong',present(value)?String(value):'—'));
  if(note)card.append(add('span',note));
  return card;
}

function evidenceReference(value){
  if(!present(value))return null;
  const row=add('div','','evidence-ref');
  row.append(add('small','Supporting Evidence'),add('code',String(value)));
  row.title='Exact evidence identifier supplied with the assessment';
  return row;
}

function factList(entries){
  const list=add('dl','','fact-list');
  for(const [label,value] of entries){
    if(!present(value))continue;
    list.append(add('dt',label),add('dd',String(value)));
  }
  return list;
}

function apiErrorMessage(body,fallback){
  if(body&&body.error&&typeof body.error.message==='string')return body.error.message;
  if(body&&typeof body.error==='string')return body.error;
  return fallback;
}

async function fetchJson(url,fallback='Request failed'){
  const response=await fetch(url);
  let body;
  try{body=await response.json();}catch(error){throw Error(fallback);}
  if(!response.ok)throw Error(apiErrorMessage(body,fallback));
  return body;
}

function currentRoute(){
  const page=window.location.hash.slice(1).toLowerCase();
  return PAGES.includes(page)?page:'dashboard';
}

function applyRoute(){
  const raw=window.location.hash.slice(1).toLowerCase();
  const page=currentRoute();
  if(raw!==page)history.replaceState(null,'','#'+page);
  document.querySelectorAll('[data-page-panel]').forEach(panel=>{panel.hidden=panel.dataset.pagePanel!==page;});
  document.querySelectorAll('#primary-nav a').forEach(link=>{
    if(link.dataset.page===page)link.setAttribute('aria-current','page');
    else link.removeAttribute('aria-current');
  });
  el('page-title').textContent=PAGE_TITLES[page];
  document.title=PAGE_TITLES[page]+' — SOCLens';
  closeNavigation();
  ensurePageRendered(page);
}

function closeNavigation(){
  document.body.classList.remove('nav-open');
  el('menu-toggle').setAttribute('aria-expanded','false');
  el('menu-toggle').setAttribute('aria-label','Open navigation');
}

function toggleNavigation(){
  const open=document.body.classList.toggle('nav-open');
  el('menu-toggle').setAttribute('aria-expanded',String(open));
  el('menu-toggle').setAttribute('aria-label',open?'Close navigation':'Open navigation');
}

function ensurePageRendered(page){
  if(renderedPages.has(page)&&page!=='settings')return;
  if(page==='settings'){
    renderSettings();
    renderedPages.add(page);
    return;
  }
  if(!current){
    renderNoAssessment(page);
    return;
  }
  const renderers={
    dashboard:renderDashboard,
    assessments:renderAssessments,
    incidents:renderIncidents,
    findings:renderFindings,
    history:renderHistory,
    reports:renderReports,
    policy:renderPolicy
  };
  renderers[page](current);
  renderedPages.add(page);
}

function renderNoAssessment(page){
  const targets={
    dashboard:'dashboard-summary',assessments:'assessment-current',incidents:'incidents-list',
    findings:'findings-list',history:'history-unavailable',reports:'report-current',policy:'policy-areas'
  };
  const target=el(targets[page]);
  if(target)target.replaceChildren(add('p','No assessment is loaded. Open Assessments to load a demonstration or import evidence.','empty-state'));
}

function setStatus(message,isError=false){
  el('status').textContent=message;
  el('status').classList.toggle('error-text',isError);
}

function assessmentLabel(){
  if(mode==='baseline')return 'Baseline synthetic assessment';
  if(mode==='degraded')return 'Degraded synthetic assessment';
  if(mode==='history')return 'Historical assessment';
  return 'Imported assessment';
}

function setAssessment(report,assessmentId=null,manifest=null){
  current=report;
  currentAssessmentId=assessmentId;
  currentManifest=manifest;
  historyState=null;
  renderedPages=new Set();
  updateDataClassification(report);
  renderDashboard(report);
  renderedPages.add('dashboard');
  setStatus(assessmentLabel()+' loaded · '+(report.scope||'Scope not reported'));
  ensurePageRendered(currentRoute());
  loadHistory(report.scope);
}

function updateDataClassification(report){
  const label=el('data-label');
  const notice=el('data-notice');
  label.textContent=report.synthetic?'Synthetic demo':'User-supplied local evidence';
  label.className='data-pill '+(report.synthetic?'synthetic':'user-data');
  notice.hidden=false;
  notice.textContent=report.synthetic
    ?'Synthetic demonstration data — not real CSE evidence and not an operational assurance claim.'
    :'User-supplied local evidence — verify authorization, provenance, and handling requirements.';
  notice.className='data-notice'+(report.synthetic?' synthetic':'');
}

function priorityCount(report){
  return (Array.isArray(report.findings)?report.findings:[]).filter(finding=>['high','critical'].includes(String(finding.priority||'').toLowerCase())).length;
}

function domainRow(name,value){
  const row=add('div','','domain-row');
  const track=add('div','','domain-track');
  const fill=add('div','','domain-fill');
  fill.style.width=Math.max(0,Math.min(100,Number(value)||0))+'%';
  track.append(fill);
  row.append(add('span',name),track,add('strong',number(value)));
  row.title=DOMAIN_HELP[name]||'Assessment area';
  return row;
}

function renderDashboard(report){
  el('dashboard-score').textContent=number(report.score);
  el('dashboard-maturity').textContent=report.maturity||'—';
  el('dashboard-confidence').textContent=number(report.confidence)+'%';
  el('dashboard-priority').textContent=String(priorityCount(report));
  el('dashboard-maturity-note').textContent=report.maturity==='Provisional'?'Evidence or sample gate not met':'Current policy result';
  const maturityCard=el('dashboard-maturity').closest('.hero-metric');
  maturityCard.classList.toggle('provisional',report.maturity==='Provisional');
  el('dashboard-priority').closest('.hero-metric').classList.toggle('attention',priorityCount(report)>0);

  const lifecycle=report.lifecycle||{};
  el('dashboard-completion').textContent=lifecycle.enabled
    ?(lifecycle.complete_incidents||0)+' / '+(lifecycle.incident_count||0)
    :'Not provided';
  el('dashboard-completion-note').textContent=lifecycle.enabled?'Completed assessed incidents':'Legacy assessment format';
  el('dashboard-change').textContent='Checking';
  el('dashboard-change-note').textContent='Loading compatible history';

  const summary=report.supervisory_summary||{};
  const container=el('dashboard-summary');
  container.replaceChildren();
  const priority=priorityCount(report);
  const evidenceDescription=report.confidence>=90?'strong':report.confidence>=70?'adequate':'limited';
  const lead=`SOC performance is ${number(report.score)} out of 100 with ${report.maturity||'unreported'} maturity. Evidence quality is ${evidenceDescription} at ${number(report.confidence)}%.`;
  container.append(add('p',lead,'lead'));
  const strongest=summary.strongest_domain&&summary.strongest_domain.name;
  const weakest=summary.weakest_domain&&summary.weakest_domain.name;
  const support=priority
    ?`${priority} High or Critical issue${priority===1?' requires':'s require'} review.${strongest&&weakest?' '+strongest+' is currently strongest; '+weakest+' is weakest.':''}`
    :`No High or Critical findings are recorded.${strongest&&weakest?' '+strongest+' is currently strongest; '+weakest+' is weakest.':''}`;
  container.append(add('p',support,'support'));
  const actions=add('div','','next-actions');
  const incidentLink=add('a','Review incidents');incidentLink.href='#incidents';
  const findingLink=add('a','Review findings');findingLink.href='#findings';
  const historyLink=add('a','View performance change');historyLink.href='#history';
  actions.append(incidentLink,findingLink,historyLink);
  container.append(actions);

  const domains=el('dashboard-domains');
  domains.replaceChildren();
  for(const name of ['Detection','Response','Telemetry','Quality','Governance']){
    domains.append(domainRow(name,report.domains&&report.domains[name]));
  }
}

function currentHistoryPoint(){
  const points=historyState&&historyState.history&&Array.isArray(historyState.history.points)?historyState.history.points:[];
  return points.find(point=>point.assessment_id===currentAssessmentId)||null;
}

function performanceChange(point){
  const delta=point&&point.previous_delta&&point.previous_delta.score;
  if(!Number.isFinite(delta))return {label:'Not enough history',className:'not-evaluated',note:'A prior compatible assessment is required'};
  if(delta>0)return {label:'Improved',className:'improved',note:signed(delta,' points since prior assessment')};
  if(delta<0)return {label:'Declined',className:'declined',note:signed(delta,' points since prior assessment')};
  return {label:'Stable',className:'stable',note:'No score change since prior assessment'};
}

function updateDashboardHistory(){
  if(historyState&&historyState.error){
    el('dashboard-change').textContent='Unavailable';
    el('dashboard-change-note').textContent='Performance history could not be loaded';
    el('dashboard-change').closest('.hero-metric').classList.add('attention');
    return;
  }
  const change=performanceChange(currentHistoryPoint());
  el('dashboard-change').textContent=change.label;
  el('dashboard-change-note').textContent=change.note;
  const card=el('dashboard-change').closest('.hero-metric');
  card.classList.toggle('attention',change.className==='declined');
}

function renderAssessments(report){
  el('assessment-status').textContent=assessmentLabel();
  const counts=report.counts||{};
  const lifecycle=report.lifecycle||{};
  const container=el('assessment-current');
  container.replaceChildren(
    detailItem('Scope / Entity',report.scope),
    detailItem('Evidence As Of',displayTime(report.as_of)),
    detailItem('Assessment Run',currentManifest?displayTime(currentManifest.assessed_at):'Run time loading'),
    detailItem('SOC Performance',number(report.score)+' / 100'),
    detailItem('Maturity',report.maturity),
    detailItem('Evidence Quality',number(report.confidence)+'%'),
    detailItem('Incident Process',lifecycle.enabled?'Enabled':'Legacy / not supplied'),
    detailItem('Evidence Reviewed',(counts.techniques||0)+' techniques · '+(counts.reviewed_cases||0)+' cases')
  );
  renderAssessmentScore(report);
  renderAssessmentHistory();
}

function renderAssessmentScore(report){
  const domains=el('assessment-domains');domains.replaceChildren();
  for(const name of ['Detection','Response','Telemetry','Quality','Governance'])domains.append(domainRow(name,report.domains&&report.domains[name]));
  const technical=el('assessment-score-technical');technical.replaceChildren();
  const factors=report.confidence_factors||{};
  const factorGrid=add('div','','technical-grid');
  factorGrid.append(
    detailItem('Evidence Completeness',number(factors.completeness,3)),
    detailItem('Evidence Freshness',number(factors.freshness,3)),
    detailItem('Evidence Traceability',number(factors.traceability,3))
  );
  technical.append(add('p','Evidence Quality factors','eyebrow'),factorGrid);
  const lifecycle=report.lifecycle||{};
  const impact=lifecycle.scoring&&lifecycle.scoring.domain_impact||{};
  const impactGrid=add('div','','technical-grid');
  for(const domain of ['Response','Quality']){
    const values=impact[domain]||{};
    const card=add('article','','stage-technical');card.append(add('h3',domain+' Score Impact'));
    card.append(factList([
      ['Legacy component',Number.isFinite(values.legacy_score)?number(values.legacy_score):null],
      ['Incident process component',Number.isFinite(values.lifecycle_score)?number(values.lifecycle_score):null],
      ['Combined score',Number.isFinite(values.combined_score)?number(values.combined_score):number(report.domains&&report.domains[domain])],
      ['Incident process effect',Number.isFinite(values.effect_points)?signed(values.effect_points,' points'):null],
      ['Legacy requirements',values.legacy_requirements],['Incident process requirements',values.lifecycle_requirements]
    ]));impactGrid.append(card);
  }
  technical.append(add('p','Score impact','eyebrow'),impactGrid);
  if(!(lifecycle.enabled&&lifecycle.scoring&&lifecycle.scoring.applied))technical.append(add('p','Incident process scoring was not applied. Response and Quality use legacy evidence components.','empty-inline'));
}

function renderAssessmentHistory(){
  const container=el('assessment-history');
  const state=el('assessment-history-state');
  if(!historyState){
    state.textContent='Loading';
    container.replaceChildren(add('p','Loading previous assessments…','loading-state'));
    return;
  }
  if(historyState.error){
    state.textContent='Unavailable';
    container.replaceChildren(add('p',historyState.error,'empty-state error-state'));
    return;
  }
  const records=historyState.records||[];
  state.textContent=records.length+' recorded';
  if(!records.length){
    container.replaceChildren(add('p','No previous assessments are available for this scope.','empty-state'));
    return;
  }
  const table=document.createElement('table');
  const caption=add('caption','Previous assessments for the current scope','sr-only');
  const head=document.createElement('thead');
  const header=document.createElement('tr');
  ['Assessment date','Score','Evidence Quality','Maturity','Incident Process','Action'].forEach(label=>header.append(add('th',label)));
  head.append(header);
  const body=document.createElement('tbody');
  for(const record of records){
    const row=document.createElement('tr');
    row.append(add('td',displayTime(record.assessed_at)),add('td',number(record.score)),add('td',number(record.confidence)+'%'),add('td',record.maturity),add('td',record.lifecycle_enabled?'Enabled':'Legacy'));
    const action=document.createElement('td');
    const button=add('button',record.assessment_id===currentAssessmentId?'Active':'Open','table-action');
    button.type='button';
    button.disabled=record.assessment_id===currentAssessmentId;
    button.onclick=()=>openHistoricalAssessment(record.assessment_id);
    action.append(button);row.append(action);body.append(row);
  }
  table.append(caption,head,body);
  container.replaceChildren(table);
}

function stageOutcome(incident,stageName){
  const stage=incident.stages&&incident.stages[stageName];
  const evaluation=incident.stage_evaluation&&incident.stage_evaluation[stageName];
  if(evaluation&&evaluation.result)return evaluation.result;
  if(stage)return 'recorded';
  if(stageName==='escalation'&&!incident.escalation_required)return 'not_required';
  return 'missing';
}

function overviewCell(label,value){
  const cell=add('span','','overview-cell');
  cell.append(add('small',label),add('b',String(value)));
  return cell;
}

function stageProcessCard(incident,stageName){
  const outcome=stageOutcome(incident,stageName);
  const evaluation=incident.stage_evaluation&&incident.stage_evaluation[stageName];
  const card=add('article','','process-stage '+outcome.replaceAll('_','-'));
  card.append(add('strong',title(stageName)),badge(outcome));
  if(evaluation&&Number.isFinite(evaluation.observed_minutes))card.append(add('small','Observed: '+minutes(evaluation.observed_minutes)));
  else if(outcome==='not_required')card.append(add('small','Not required for this incident'));
  else if(outcome==='missing')card.append(add('small','No stage was recorded'));
  else card.append(add('small','Stage recorded'));
  return card;
}

function technicalStage(incident,stageName){
  const stage=incident.stages&&incident.stages[stageName];
  const evaluation=incident.stage_evaluation&&incident.stage_evaluation[stageName];
  const outcome=stageOutcome(incident,stageName);
  const card=add('article','','stage-technical');
  const heading=add('h3');heading.append(add('span',title(stageName)),badge(outcome));card.append(heading);
  card.append(factList([
    ['Timestamp',stage&&stage.timestamp],['Stage status',stage&&stage.status],
    ['Observed delay',evaluation&&Number.isFinite(evaluation.observed_minutes)?minutes(evaluation.observed_minutes):null],
    ['Expected target',evaluation&&Number.isFinite(evaluation.threshold_minutes)?minutes(evaluation.threshold_minutes):null],
    ['Earned credit',evaluation&&Number.isFinite(evaluation.credit)?number(evaluation.credit):null]
  ]));
  const evidence=stage&&evidenceReference(stage.evidence_ref);
  if(evidence)card.append(evidence);
  return card;
}

function incidentDetails(incident,index){
  const details=add('details','','incident');
  details.id='incident-'+(index+1);
  details.dataset.incidentId=incident.incident_id||'';
  const summary=document.createElement('summary');
  const identity=add('span','','incident-identity');
  const alertIds=Array.isArray(incident.alert_ids)?incident.alert_ids:[incident.alert_id].filter(Boolean);
  const sourceIds=Array.isArray(incident.source_ids)?incident.source_ids:[incident.source_id].filter(Boolean);
  const caseId=incident.primary_case_id||incident.case_id;
  const priorityFindings=(current&&Array.isArray(current.findings)?current.findings:[]).filter(finding=>finding.incident_id===incident.incident_id&&['high','critical'].includes(String(finding.priority||'').toLowerCase())).length;
  identity.append(add('strong',incident.incident_id||'Unknown incident'),add('small',(caseId||'No case')+' · '+alertIds.length+' alert'+(alertIds.length===1?'':'s')));
  const overview=add('span','','incident-overview');
  overview.append(
    overviewCell('Alerts',alertIds.length),overviewCell('Sources',sourceIds.length),overviewCell('Completion',incident.complete?'Complete':'Incomplete'),
    overviewCell('Investigation',title(stageOutcome(incident,'investigation'))),
    overviewCell('Escalation',title(stageOutcome(incident,'escalation'))),
    overviewCell('Response',title(stageOutcome(incident,'response'))),
    overviewCell('Closure',title(stageOutcome(incident,'closure'))),
    overviewCell('Priority Findings',priorityFindings),overviewCell('Total time',minutes(incident.timing_minutes&&incident.timing_minutes.total_lifecycle))
  );
  summary.append(identity,overview);details.append(summary);

  const body=add('div','','incident-body');
  const process=add('div','','process-line');
  STAGES.forEach(stage=>process.append(stageProcessCard(incident,stage)));
  body.append(process);
  const timings=add('div','','timing-strip');
  for(const [key,label] of Object.entries(TIMINGS))timings.append(summaryCard(label,minutes(incident.timing_minutes&&incident.timing_minutes[key])));
  body.append(timings);

  if(alertIds.length){
    const related=add('section','','incident-context');related.append(add('p','Related Alerts','eyebrow'));
    const chips=add('div','','timing-strip');for(const alertId of alertIds)chips.append(badge(alertId,'recorded'));related.append(chips);body.append(related);
  }
  const actions=Array.isArray(incident.response_actions)?incident.response_actions:[];
  if(actions.length){
    const section=add('section','','incident-context');section.append(add('p','Response Actions','eyebrow'));
    const grid=add('div','','technical-grid');for(const action of actions){const card=add('article','','stage-technical');card.append(add('h3',action.action_type||'Response action'),factList([['Time',action.timestamp],['Status',action.status],['Milestone',action.milestone],['Canonical response',action.canonical_response?'Yes':'No']]));const evidence=evidenceReference(action.evidence_ref);if(evidence)card.append(evidence);grid.append(card);}section.append(grid);body.append(section);
  }
  const recovery=Array.isArray(incident.recovery_events)?incident.recovery_events:[];
  if(recovery.length)body.append(add('p',`${recovery.length} explicit recovery event${recovery.length===1?' was':'s were'} recorded after response.`,'empty-inline'));
  if(Array.isArray(incident.reasons)&&incident.reasons.length){const explanation=add('section','','incident-context');explanation.append(add('p','Correlation Explanation','eyebrow'));const list=document.createElement('ul');list.className='rule-list';incident.reasons.forEach(reason=>list.append(add('li',reason)));explanation.append(list);body.append(explanation);}

  const technical=add('details','','panel disclosure');
  technical.append(add('summary','Show technical details'));
  const technicalContent=add('div','','technical-content');
  technicalContent.append(factList([
    ['Incident ID',incident.incident_id],['Primary alert ID',incident.alert_id],['Alert IDs',alertIds.join(', ')],['Case ID',caseId],
    ['Source IDs',sourceIds.join(', ')],['First detection',incident.first_detection_at],['Latest related detection',incident.latest_detection_at],
    ['Correlation version',incident.correlation_version],['Correlation strength',incident.correlation_strength],
    ['Correlation rules',(incident.rule_ids||[]).join(', ')],['Source import IDs',(incident.source_import_ids||[]).join(', ')],
    ['Escalation required',incident.escalation_required?'Yes':'No'],['Correlation complete',incident.complete?'Yes':'No']
  ]));
  const stages=add('div','','technical-grid');
  STAGES.forEach(stage=>stages.append(technicalStage(incident,stage)));
  technicalContent.append(stages);technical.append(technicalContent);body.append(technical);details.append(body);
  return details;
}

function renderIncidents(report){
  const lifecycle=report.lifecycle||{};
  const correlation=report.correlation||{};
  const assessedIncidents=Array.isArray(lifecycle.incidents)?lifecycle.incidents:[];
  const incidents=assessedIncidents.length?assessedIncidents:(Array.isArray(correlation.incidents)?correlation.incidents:[]);
  const summary=el('incidents-summary');
  const list=el('incidents-list');
  const technicalOverview=el('incidents-technical-overview');
  summary.replaceChildren();list.replaceChildren();
  if(!lifecycle.enabled&&!report.correlation){
    summary.hidden=true;technicalOverview.hidden=true;
    list.append(add('p','Incident process evidence was not provided. This legacy assessment uses source, technique, case, and control evidence only.','empty-state'));
    return;
  }
  if(!incidents.length){
    summary.hidden=true;technicalOverview.hidden=true;
    list.append(add('p','Incident process mode is enabled, but no assessed incidents were supplied.','empty-state'));
    return;
  }
  summary.hidden=false;
  technicalOverview.hidden=!lifecycle.enabled;
  const incomplete=Math.max(0,(lifecycle.incident_count||incidents.length)-(lifecycle.complete_incidents||0));
  const components=lifecycle.scoring&&lifecycle.scoring.components||{};
  summary.append(
    summaryCard('Assessed Incidents',lifecycle.incident_count||incidents.length),
    summaryCard('Complete',lifecycle.complete_incidents||0),
    summaryCard('Incomplete',incomplete),
    summaryCard('Delayed or Missing',Object.values(components).reduce((sum,component)=>sum+(component.delayed||0)+(component.missing||0),0)),
    summaryCard('Unmatched Alerts',(correlation.unmatched_alerts||[]).length),summaryCard('Correlation Conflicts',(correlation.conflicts||[]).length)
  );
  renderIncidentTechnicalSummary(report);
  if((correlation.conflicts||[]).length||(correlation.unmatched_alerts||[]).length){
    const notice=add('article','','panel compact-panel');notice.append(add('p','Correlation review required','eyebrow'));
    const list=document.createElement('ul');list.className='rule-list';
    (correlation.conflicts||[]).forEach(conflict=>list.append(add('li',`${conflict.code}: ${conflict.reason}`)));
    (correlation.unmatched_alerts||[]).forEach(alert=>list.append(add('li',`${alert.alert_id||alert.identity}: no explicit incident, case, or parent association was supplied.`)));
    notice.append(list);el('incidents-list').append(notice);
  }
  incidents.forEach((incident,index)=>list.append(incidentDetails(incident,index)));
}

function renderIncidentTechnicalSummary(report){
  const lifecycle=report.lifecycle||{};
  const scoring=lifecycle.scoring||{};
  const components=scoring.components||{};
  const container=el('incidents-technical-summary');container.replaceChildren();
  const trace=add('div','','detail-grid');
  trace.append(
    detailItem('Response Area',number(report.domains&&report.domains.Response)),
    detailItem('Operational Response',number(scoring.operational_response&&scoring.operational_response.score)),
    detailItem('Quality Area',number(report.domains&&report.domains.Quality)),
    detailItem('Closure Discipline',number(scoring.closure_discipline&&scoring.closure_discipline.score))
  );
  container.append(add('p','Score trace','eyebrow'),trace,add('p','Process component outcomes','eyebrow'));
  const wrap=add('div','','table-wrap');const table=document.createElement('table');const caption=add('caption','Incident process component outcomes','sr-only');const head=document.createElement('thead');const header=document.createElement('tr');
  ['Component','Score','Applicable','Timely','Delayed','Missing','Unmeasured','Not Applicable'].forEach(label=>header.append(add('th',label)));head.append(header);
  const body=document.createElement('tbody');
  for(const name of ['investigation','escalation','response','closure']){
    const component=components[name];if(!component)continue;const row=document.createElement('tr');
    [title(name),number(component.score),component.applicable,component.timely,component.delayed,component.missing,component.unmeasured,component.not_applicable].forEach(value=>row.append(add('td',present(value)?String(value):'—')));body.append(row);
  }
  table.append(caption,head,body);wrap.append(table);container.append(wrap,add('p','Average process timings','eyebrow'));
  const timings=add('div','','detail-grid');
  for(const [key,label] of Object.entries(TIMINGS)){
    const metric=lifecycle.timing_metrics&&lifecycle.timing_metrics[key]||{};
    timings.append(detailItem(label,minutes(metric.average_minutes),Number.isFinite(metric.count)?metric.count+' measured':'No measurements'));
  }
  container.append(timings);
}

function findingArea(finding){
  if(finding.stage==='closure')return 'Quality';
  if(['investigation','escalation','response'].includes(finding.stage))return 'Response';
  const text=((finding.title||'')+' '+(finding.owner||'')).toLowerCase();
  if(text.includes('detection')||text.includes('validate'))return 'Detection';
  if(text.includes('fresh')||text.includes('platform'))return 'Telemetry';
  if(text.includes('control')||text.includes('governance'))return 'Governance';
  return 'Assessment';
}

function friendlyFindingTitle(finding){
  const stage=String(finding.stage||'');
  const kind=String(finding.finding_type||'');
  if(stage&&kind){
    if(stage==='escalation'&&kind==='missing')return 'Required escalation missing';
    if(kind==='missing')return title(stage)+' step missing';
    if(kind==='delayed')return title(stage)+' completed late';
    if(kind==='unmeasured')return title(stage)+' timing not measurable';
  }
  return finding.title||'Assessment issue';
}

function expectedFindingResult(finding){
  if(Number.isFinite(finding.policy_threshold_minutes))return 'Within '+minutes(finding.policy_threshold_minutes);
  if(finding.finding_type==='missing'&&finding.stage)return 'A recorded '+finding.stage+' stage';
  return 'The configured assessment requirement should be evidenced';
}

function observedFindingResult(finding){
  if(Number.isFinite(finding.observed_minutes))return minutes(finding.observed_minutes);
  if(finding.finding_type==='missing')return 'Not recorded';
  if(finding.finding_type==='unmeasured')return 'Timing unavailable';
  return finding.reason||'Requirement not met';
}

function openIncident(incidentId){
  window.location.hash='#incidents';
  ensurePageRendered('incidents');
  window.setTimeout(()=>{
    const target=[...document.querySelectorAll('.incident')].find(node=>node.dataset.incidentId===incidentId);
    if(target){target.open=true;target.scrollIntoView({block:'start'});target.querySelector('summary').focus();}
  },0);
}

function findingDetails(finding){
  const severity=String(finding.priority||'Unspecified');
  const details=add('details','','finding severity-'+severity.toLowerCase());
  const summary=document.createElement('summary');
  const identity=add('span','','finding-identity');
  identity.append(add('strong',friendlyFindingTitle(finding)),add('small',findingArea(finding)+(finding.incident_id?' · '+finding.incident_id:'')));
  const meta=add('span','','finding-summary-meta');
  meta.append(badge(severity,'priority'),badge(findingArea(finding)));
  summary.append(identity,meta);details.append(summary);
  const body=add('div','','finding-body');
  const explanation=add('div','','finding-explanation');
  const relatedAlerts=Array.isArray(finding.alert_ids)?finding.alert_ids:[];
  const happened=relatedAlerts.length>1?`${relatedAlerts.length} alerts were correlated to ${finding.incident_id}, and ${friendlyFindingTitle(finding).toLowerCase()}.`:friendlyFindingTitle(finding);
  const blocks=[
    ['What happened',happened],['Why it matters',finding.reason||'The configured requirement was not met.'],
    ['Expected target',expectedFindingResult(finding)],['Observed result',observedFindingResult(finding)],
    ['Affected incident',finding.incident_id||finding.case_id||'Not incident-specific'],['Supporting evidence',finding.evidence_ref||'No evidence identifier supplied']
  ];
  for(const [heading,text] of blocks){const block=add('div','','explanation-block');block.append(add('h3',heading),add('p',text));explanation.append(block);}
  if(relatedAlerts.length){const block=add('div','','explanation-block');block.append(add('h3','Related alerts'),add('p',relatedAlerts.join(', ')));explanation.append(block);}
  body.append(explanation);
  if(finding.incident_id){
    const button=add('button','Open affected incident');button.type='button';button.onclick=()=>openIncident(finding.incident_id);body.append(button);
  }
  const technical=add('details','','panel disclosure');
  technical.append(add('summary','Show technical details'));
  const content=add('div','','technical-content');
  content.append(factList([
    ['Original title',finding.title],['Finding type',finding.finding_type],['Raw stage',finding.stage],['Owner',finding.owner],
    ['Incident ID',finding.incident_id],['Alert ID',finding.alert_id],['Case ID',finding.case_id],
    ['Policy threshold',Number.isFinite(finding.policy_threshold_minutes)?minutes(finding.policy_threshold_minutes):null],
    ['Observed minutes',Number.isFinite(finding.observed_minutes)?minutes(finding.observed_minutes):null]
  ]));
  const evidence=evidenceReference(finding.evidence_ref);if(evidence)content.append(evidence);
  technical.append(content);body.append(technical);details.append(body);
  return details;
}

function renderFindings(report){
  const findings=Array.isArray(report.findings)?report.findings:[];
  const container=el('findings-list');
  el('findings-state').textContent=findings.length+' finding'+(findings.length===1?'':'s');
  container.replaceChildren();
  if(!findings.length){
    container.append(add('p','No configured policy gaps were found in this assessment.','empty-state'));
    return;
  }
  findings.forEach(finding=>container.append(findingDetails(finding)));
}

function svgNode(name,attributes={},textValue=''){
  const node=document.createElementNS('http://www.w3.org/2000/svg',name);
  for(const [key,value] of Object.entries(attributes))node.setAttribute(key,String(value));
  if(textValue)node.textContent=textValue;
  return node;
}

function renderTrendChart(points){
  const container=el('trend-chart');container.replaceChildren();
  if(!points.length){container.append(add('p','No compatible historical observations are available.','empty-inline'));return;}
  const width=900,height=230,left=48,right=24,top=20,bottom=48;
  const chartWidth=width-left-right,chartHeight=height-top-bottom;
  const x=index=>points.length===1?left+chartWidth/2:left+chartWidth*index/(points.length-1);
  const y=value=>top+chartHeight-Math.max(0,Math.min(100,value))*chartHeight/100;
  const svg=svgNode('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'Overall SOC performance by assessment date'});
  for(const mark of [0,25,50,75,100]){
    const position=y(mark);svg.append(svgNode('line',{x1:left,y1:position,x2:width-right,y2:position,class:'trend-grid'}));
    svg.append(svgNode('text',{x:left-9,y:position+4,class:'trend-axis','text-anchor':'end'},String(mark)));
  }
  const coordinates=points.map((point,index)=>`${x(index)},${y(point.score)}`).join(' ');
  if(points.length>1)svg.append(svgNode('polyline',{points:coordinates,class:'trend-line'}));
  points.forEach((point,index)=>{
    const horizontal=x(index),vertical=y(point.score);const group=svgNode('g',{class:'trend-point'});
    group.append(svgNode('circle',{cx:horizontal,cy:vertical,r:5}),svgNode('text',{x:horizontal,y:vertical-11,'text-anchor':'middle',class:'trend-value'},number(point.score)),svgNode('text',{x:horizontal,y:height-20,'text-anchor':'middle',class:'trend-date'},String(point.assessed_at||'').slice(0,10)),svgNode('title',{},`${displayTime(point.assessed_at)} · score ${number(point.score)}`));svg.append(group);
  });container.append(svg);
}

function deltaGrid(delta){
  const container=add('div','','delta-grid');
  const entries=[['Overall',delta&&delta.score],['Evidence Quality',delta&&delta.confidence]];
  for(const name of ['Detection','Response','Telemetry','Quality','Governance'])entries.push([name,delta&&delta.domains&&delta.domains[name]]);
  for(const [label,value] of entries){
    const card=summaryCard(label,signed(value,' pts'));
    if(Number.isFinite(value))card.classList.add(value>0?'positive':value<0?'negative':'neutral');
    container.append(card);
  }
  return container;
}

function renderHistorySummary(history){
  const container=el('history-summary');const latest=el('history-latest-delta');container.replaceChildren();latest.replaceChildren();
  const summary=history.summary;
  if(!summary){latest.append(add('p','A second compatible assessment is required to show performance change.','empty-inline'));return;}
  container.append(summaryCard('Current Score',number(summary.current)),summaryCard('Previous Change',signed(summary.previous_delta&&summary.previous_delta.score,' pts')),summaryCard('Best Score',number(summary.best&&summary.best.score)),summaryCard('Direction',title(summary.direction)));
  latest.append(add('p','Latest compatible performance change','eyebrow'));
  if(summary.previous_delta)latest.append(deltaGrid(summary.previous_delta));
  else latest.append(add('p','A second compatible assessment is required to show performance change.','empty-inline'));
}

function historyOption(record){
  const option=document.createElement('option');option.value=record.assessment_id;
  option.textContent=String(record.assessed_at||'').slice(0,10)+' · '+number(record.score)+' · '+record.maturity;return option;
}

function renderHistorySelections(points){
  const before=el('history-before'),after=el('history-after'),button=el('history-compare');before.replaceChildren();after.replaceChildren();
  points.forEach(point=>{before.append(historyOption(point));after.append(historyOption(point));});
  const enabled=points.length>=2;before.disabled=!enabled;after.disabled=!enabled;button.disabled=!enabled;
  if(enabled){before.value=points[points.length-2].assessment_id;after.value=points[points.length-1].assessment_id;}
  const comparison=el('history-comparison');comparison.replaceChildren();
  if(!enabled)comparison.append(add('p','At least two compatible assessments are required for comparison.','empty-inline'));
}

function historyChangeBadge(record,point){
  if(!point)return badge('Incompatible');
  const change=performanceChange(point);
  const result=badge(change.label,change.className);
  if(point.drift&&point.drift.detected)result.title='Technical drift rules were triggered';
  return result;
}

function renderHistoryTable(records,points){
  const body=el('history-table');body.replaceChildren();const pointById=new Map(points.map(point=>[point.assessment_id,point]));
  for(const record of records){
    const row=document.createElement('tr');
    const id=document.createElement('th');id.scope='row';id.textContent=record.assessment_id;row.append(id);
    row.append(add('td',displayTime(record.assessed_at)),add('td',number(record.score)),add('td',number(record.confidence)+'%'),add('td',record.maturity),add('td',record.lifecycle_enabled?'Enabled':'Legacy'));
    const change=document.createElement('td');change.append(historyChangeBadge(record,pointById.get(record.assessment_id)));row.append(change);
    const action=document.createElement('td');const button=add('button','Open','table-action');button.type='button';button.onclick=()=>openHistoricalAssessment(record.assessment_id);action.append(button);row.append(action);body.append(row);
  }
}

function renderHistory(report){
  const content=el('history-content'),unavailable=el('history-unavailable');
  if(!historyState){content.hidden=true;unavailable.hidden=false;unavailable.className='empty-state';unavailable.textContent='Loading persisted assessments…';return;}
  if(historyState.error){content.hidden=true;unavailable.hidden=false;unavailable.className='empty-state error-state';unavailable.textContent=historyState.error;el('history-state').textContent='Unavailable';return;}
  const records=historyState.records||[];const history=historyState.history||{};const points=Array.isArray(history.points)?history.points:[];
  if(!records.length){content.hidden=true;unavailable.hidden=false;unavailable.className='empty-state';unavailable.textContent='No persisted assessments are available for this scope.';el('history-state').textContent='No history';return;}
  unavailable.hidden=true;content.hidden=false;el('history-state').textContent=records.length+' assessment'+(records.length===1?'':'s');
  if(history.excluded_incompatible)el('history-state').textContent+=` · ${history.excluded_incompatible} outside current comparison set`;
  renderHistorySummary(history);renderTrendChart(points);renderHistorySelections(points);renderHistoryTable(records,points);
}

function renderHistoryComparison(result){
  const container=el('history-comparison');container.replaceChildren();const heading=add('div','','comparison-heading');
  heading.append(add('strong','Performance change'),badge(result.drift_detected?'Needs attention':'No significant change',result.drift_detected?'needs-attention':'stable'));container.append(heading,deltaGrid({score:result.score_delta,confidence:result.confidence_delta,domains:result.domain_delta}));
  const drift=result.drift||{};
  if(Array.isArray(drift.reasons)&&drift.reasons.length){
    container.append(add('p','Technical drift reasons','eyebrow'));const list=add('ul','','drift-reasons');drift.reasons.forEach(reason=>list.append(add('li',reason)));container.append(list);
  }else container.append(add('p','No configured historical drift rule was triggered.','empty-inline'));
}

async function runHistoryComparison(){
  const before=el('history-before').value,after=el('history-after').value,container=el('history-comparison');
  if(!before||!after)return;
  if(before===after){container.replaceChildren(add('p','Choose two different assessments.','empty-inline'));return;}
  container.replaceChildren(add('p','Comparing assessments…','loading-state'));
  try{
    const result=await fetchJson('/api/history/compare?before='+encodeURIComponent(before)+'&after='+encodeURIComponent(after),'Assessment comparison failed');renderHistoryComparison(result);
  }catch(error){container.replaceChildren(add('p',error.message,'empty-state error-state'));}
}

async function getStoredAssessment(assessmentId){
  if(storedCache.has(assessmentId))return storedCache.get(assessmentId);
  const stored=await fetchJson('/api/history/'+encodeURIComponent(assessmentId),'Assessment could not be opened');storedCache.set(assessmentId,stored);return stored;
}

async function openHistoricalAssessment(assessmentId){
  setStatus('Opening historical assessment…');
  try{
    const stored=await getStoredAssessment(assessmentId);mode='history';
    if(!stored.report.supervisory_summary&&stored.supervisory_summary)stored.report={...stored.report,supervisory_summary:stored.supervisory_summary};
    setAssessment(stored.report,stored.assessment.assessment_id,stored.manifest);window.location.hash='#assessments';
    setStatus('Historical assessment opened · '+displayTime(stored.assessment.assessed_at));
  }catch(error){setStatus(error.message,true);}
}

async function loadHistory(scope){
  const request=++historyRequest;historyState=null;
  if(!scope){historyState={error:'No scope is available for historical lookup.'};refreshHistoryConsumers();return;}
  try{
    let historyPromise=historyCache.get(scope);
    if(!historyPromise){
      const encoded=encodeURIComponent(scope);
      historyPromise=Promise.all([fetchJson('/api/history?scope='+encoded,'Assessment history unavailable'),fetchJson('/api/history/trend?scope='+encoded,'Performance history unavailable')]);
      historyCache.set(scope,historyPromise);
    }
    const [[listing,history],stored]=await Promise.all([
      historyPromise,
      currentAssessmentId?getStoredAssessment(currentAssessmentId).catch(()=>null):Promise.resolve(null)
    ]);
    if(request!==historyRequest)return;
    if(stored&&currentAssessmentId===stored.assessment.assessment_id)currentManifest=stored.manifest;
    historyState={records:Array.isArray(listing.assessments)?listing.assessments:[],history};
    refreshHistoryConsumers();
  }catch(error){
    if(request!==historyRequest)return;
    historyCache.delete(scope);historyState={error:error.message};refreshHistoryConsumers();
  }
}

function refreshHistoryConsumers(){
  updateDashboardHistory();
  if(renderedPages.has('assessments'))renderAssessments(current);
  if(renderedPages.has('history'))renderHistory(current);
  if(renderedPages.has('reports'))renderReports(current);
  if(renderedPages.has('policy'))renderPolicy(current);
}

function renderReports(report){
  el('download-audit').disabled=!currentAssessmentId;
  const container=el('report-current');
  container.replaceChildren(
    detailItem('Assessment Identifier',currentAssessmentId||'Not yet available'),
    detailItem('Assessment Run',currentManifest?displayTime(currentManifest.assessed_at):'Run time loading'),
    detailItem('Report Schema',report.report_schema_version||'Legacy / unversioned'),
    detailItem('Audit Package',currentAssessmentId?'Available':'Requires a stored assessment')
  );
  const provenance=el('report-provenance');provenance.replaceChildren();
  provenance.append(factList([
    ['Scope',report.scope],['Evidence as of',report.as_of],['Assessment ID',currentAssessmentId],
    ['Input SHA-256',report.sha256],['Scope SHA-256',report.scope_sha256],['Policy identifier',report.policy&&report.policy.id],
    ['Report schema',report.report_schema_version],['Database schema',currentManifest&&currentManifest.database_schema_version],
    ['Manifest schema',currentManifest&&currentManifest.manifest_schema_version],['Audit package version',currentManifest&&currentManifest.audit_package_version],
    ['Data classification',report.data_classification]
  ]));
  const ingestion=report.ingestion_provenance;
  if(ingestion&&Array.isArray(ingestion.imports)){
    provenance.append(add('p','Imported-source lineage','eyebrow'),factList([
      ['Ingestion time',ingestion.ingested_at],['Canonical evidence SHA-256',ingestion.canonical_evidence_sha256],
      ['Import IDs',ingestion.imports.map(item=>item.import_id).join(', ')],
      ['Source profiles',ingestion.imports.map(item=>`${item.source_profile} (${item.mapping_profile_id}@${item.mapping_profile_version})`).join('; ')],
      ['Source file SHA-256',ingestion.imports.map(item=>`${item.filename}: ${item.file_sha256}`).join('; ')]
    ]));
  }
}

function policyCard(label,value,note){
  const card=add('article','','policy-card');card.append(add('span',label),add('strong',value),add('span',note||''));return card;
}

function renderPolicy(report){
  const policy=report.policy||{};const weights=policy.weights||{};const areas=el('policy-areas');areas.replaceChildren();
  for(const name of ['Detection','Response','Telemetry','Quality','Governance'])areas.append(policyCard(name,Number.isFinite(weights[name])?Math.round(weights[name]*100)+'%':'—',DOMAIN_HELP[name]));
  const lifecycle=policy.lifecycle||{};const targets=el('policy-targets');targets.replaceChildren();
  [['Investigation',lifecycle.investigation_target_minutes],['Required Escalation',lifecycle.escalation_target_minutes],['Response',lifecycle.response_target_minutes],['Closure',lifecycle.closure_target_minutes]].forEach(([label,value])=>targets.append(policyCard(label,Number.isFinite(value)?value+' min':'—','Expected target')));
  const maturity=el('policy-maturity');maturity.replaceChildren();
  [['L1','Below 40'],['L2','40–59.9'],['L3','60–79.9'],['L4','80 or above, with additional detection gates']].forEach(([level,range])=>{const row=add('div','','maturity-row');row.append(add('strong',level),add('span',range));maturity.append(row);});
  const rules=el('policy-rules');rules.replaceChildren();const list=add('ul','','rule-list');
  [`Evidence Quality below ${policy.confidence_floor??70}% makes the assessment Provisional.`, `Fewer than ${policy.minimum_reviewed_cases??10} reviewed cases makes the assessment Provisional.`, 'An empty required evidence area makes the assessment Provisional.', 'A missing critical control caps maturity at L2.', 'L4 requires Detection of at least 75 with no unvalidated high-risk technique.'].forEach(rule=>list.append(add('li',rule)));rules.append(list);
  const technical=el('policy-technical');technical.replaceChildren();technical.append(factList([
    ['Policy identifier',policy.id],['Report schema',report.report_schema_version],['Database schema',currentManifest&&currentManifest.database_schema_version],
    ['Confidence floor',policy.confidence_floor],['Minimum reviewed cases',policy.minimum_reviewed_cases],['Maximum test age',Number.isFinite(policy.max_test_age_days)?policy.max_test_age_days+' days':null],
    ['Timely credit',lifecycle.timely_credit],['Delayed credit',lifecycle.delayed_credit],['Missing credit',lifecycle.missing_credit]
  ]));
}

function renderSettings(){
  const grid=el('settings-grid'),status=el('settings-status'),message=el('settings-message');grid.replaceChildren();message.replaceChildren();
  if(!serviceState){status.textContent='Checking';grid.append(add('p','Checking service readiness…','loading-state'));return;}
  if(serviceState.error){
    status.textContent='Unavailable';status.className='count-badge badge needs-attention';grid.append(detailItem('Service Status','Unavailable'),detailItem('Readiness','Could not be checked'));message.append(add('p',serviceState.error,'empty-state error-state'));return;
  }
  const database=serviceState.database||{};const ready=serviceState.status==='ready';status.textContent=ready?'Ready':'Needs attention';status.className='count-badge badge '+(ready?'ready':'needs-attention');
  grid.append(
    detailItem('Environment',title(serviceState.environment)),detailItem('Service Status',ready?'Running and ready':'Running, not ready'),
    detailItem('Application Version',serviceState.version),detailItem('Active Policy',serviceState.policy_version),
    detailItem('Database Readiness',database.ready?'Ready':'Not ready'),detailItem('Database Schema',database.schema_version??'Unavailable'),
    detailItem('Report Schema',serviceState.report_schema_version),detailItem('Runtime Directories',serviceState.directories_ready?'Ready':'Not ready')
  );
  if(!ready)message.append(add('p','One or more local dependencies are not ready. Review the service logs and runtime configuration.','empty-state error-state'));
}

async function loadServiceStatus(){
  try{
    const response=await fetch('/api/ready');let body;
    try{body=await response.json();}catch(error){throw Error('Readiness response was not valid JSON');}
    serviceState=body;
    const ready=response.ok&&body.status==='ready';
    const indicator=el('service-indicator');indicator.className='service-pill '+(ready?'ready':'problem');indicator.replaceChildren(add('span'),document.createTextNode(ready?`${title(body.environment)} · Ready`:'Service needs attention'));
  }catch(error){
    serviceState={error:'Service readiness could not be checked.'};const indicator=el('service-indicator');indicator.className='service-pill problem';indicator.replaceChildren(add('span'),document.createTextNode('Status unavailable'));
  }
  if(currentRoute()==='settings')renderSettings();
}

function downloadReport(){
  if(!current){setStatus('No assessment is available to export.',true);return;}
  const link=document.createElement('a');const url=URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:'application/json'}));
  link.href=url;link.download='soclens-assessment.json';link.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus('Assessment report exported.');
}

async function downloadAudit(){
  if(!currentAssessmentId)return;
  setStatus('Preparing audit package…');
  try{
    const response=await fetch('/api/audit/'+encodeURIComponent(currentAssessmentId));
    if(!response.ok){const error=await response.json();throw Error(apiErrorMessage(error,'Audit package export failed'));}
    const link=document.createElement('a');const url=URL.createObjectURL(await response.blob());link.href=url;link.download='soclens-audit-'+currentAssessmentId+'.zip';link.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus('Audit package exported for '+currentAssessmentId+'.');
  }catch(error){setStatus(error.message,true);}
}

function selectedImportProfile(){return importProfiles.find(profile=>profile.key===el('import-profile').value);}

function renderMappingProfile(){
  const profile=selectedImportProfile(),container=el('mapping-technical');container.replaceChildren();
  if(!profile){container.append(add('p','Select a profile to view its exact field mapping.','muted'));return;}
  container.append(factList([['Profile',profile.label],['Identifier',profile.key],['Accepted format',profile.formats.join(', ')],['Canonical category',profile.category]]));
  const mapping=Object.entries(profile.field_mapping||{});
  if(mapping.length){const list=document.createElement('dl');list.className='fact-list';for(const [source,target] of mapping){list.append(add('dt',source),add('dd',target));}container.append(list);}
  else container.append(add('p','Canonical SOCLens JSON is validated without source-field remapping.','muted'));
}

function importIssueText(issue){
  const location=issue.record_number?`Record ${issue.record_number}${issue.field?` · ${issue.field}`:''}`:(issue.field||'File');
  return `${location} · ${issue.code} · ${issue.reason}`;
}

function renderImportWorkspace(){
  const container=el('import-preview');container.replaceChildren();
  el('import-status').textContent=stagedImports.length?`${stagedImports.length} staged`:'No imports';
  el('clear-imports').disabled=!stagedImports.length;el('preview-build').disabled=!stagedImports.length;el('run-import-assessment').disabled=!buildReady;
  if(!stagedImports.length)container.append(add('p','No evidence files are staged.','empty-state'));
  for(const job of stagedImports){
    const card=add('article','',`import-card ${job.status==='ready'?'':'failed'}`);const head=add('div','', 'import-card-head');
    const identity=document.createElement('div');identity.append(add('h4',job.original_filename),add('p',`${job.source_profile} · ${job.status}`));head.append(identity,badge(job.status==='ready'?'READY':'ERROR',job.status==='ready'?'ready':'missing'));card.append(head);
    card.append(factList([['File SHA-256',job.file_sha256],['Records',job.record_count],['Accepted',job.accepted_records],['Rejected',job.rejected_records],['Warnings',job.warnings],['Produces',(job.categories_produced||[]).join(', ')||'None']]));
    const issues=Array.isArray(job.issues)?job.issues:[];
    if(issues.length){const list=document.createElement('ul');list.className='issue-list';for(const issue of issues.slice(0,12)){const item=add('li',importIssueText(issue),`issue-${String(issue.level).toLowerCase()}`);list.append(item);}card.append(list);}
    const actions=add('div','', 'import-card-actions');const remove=add('button','Remove','table-action');remove.type='button';remove.onclick=()=>removeImport(job.import_id);actions.append(remove);
    if(job.rejected_records){const errors=add('a','Download errors','text-link');errors.href=`/api/import/${encodeURIComponent(job.import_id)}/errors?format=csv`;errors.download=`soclens-import-errors-${job.import_id}.csv`;actions.append(errors);}
    card.append(actions);container.append(card);
  }
  renderLocalCoverage();
}

function renderCoverage(coverage){
  const container=el('build-coverage');container.replaceChildren();
  for(const category of ['sources','techniques','cases','controls','lifecycles']){
    const value=coverage&&coverage[category]||{state:'missing',records:0};const card=add('div','', 'coverage-item');card.append(add('small',title(category)),add('strong',`${title(value.state)} · ${value.records||0}`));container.append(card);
  }
}

function renderLocalCoverage(){
  const coverage={};for(const category of ['sources','techniques','cases','controls','lifecycles'])coverage[category]={state:'missing',records:0};
  for(const job of stagedImports.filter(item=>item.status==='ready'))for(const category of job.categories_produced||[]){if(coverage[category]){coverage[category].state='staged';coverage[category].records+=job.accepted_records||0;}}
  renderCoverage(coverage);buildReady=false;el('run-import-assessment').disabled=true;
  el('build-message').textContent=stagedImports.length?'Check combined evidence to validate correlations and required coverage.':'Upload evidence to begin a multi-file assessment.';
}

async function loadImportProfiles(){
  try{
    const body=await fetchJson('/api/import/profiles','Import profiles could not be loaded');importProfiles=body.profiles||[];const select=el('import-profile');select.replaceChildren();
    for(const profile of importProfiles){const option=document.createElement('option');option.value=profile.key;option.textContent=profile.label+` · v${profile.version}`;select.append(option);}renderMappingProfile();
  }catch(error){el('import-profile').replaceChildren(add('option','Profiles unavailable'));setStatus(error.message,true);}
}

async function stageImport(){
  const file=el('upload').files[0],profile=selectedImportProfile();if(!profile){setStatus('Choose a mapping profile.',true);return;}if(!file){setStatus('Choose an evidence file.',true);return;}
  const sourceFormat=file.name.toLowerCase().endsWith('.csv')?'csv':file.name.toLowerCase().endsWith('.json')?'json':'';
  if(!sourceFormat){setStatus('Evidence file must use a .csv or .json extension.',true);return;}
  try{
    setStatus('Validating and mapping evidence…');const query=new URLSearchParams({profile:profile.key,filename:file.name,format:sourceFormat});
    const response=await fetch('/api/import?'+query,{method:'POST',headers:{'Content-Type':sourceFormat==='csv'?'text/csv':'application/json'},body:file});const body=await response.json();
    if(!response.ok)throw Error(apiErrorMessage(body,'Evidence import failed'));stagedImports.push(body);renderImportWorkspace();await syncPreparationSession();setStatus(body.status==='ready'?'Evidence mapped and ready for combined validation.':'Evidence contains errors; review the import preview.',body.status!=='ready');
  }catch(error){setStatus(error.message,true);}finally{el('upload').value='';}
}

async function removeImport(importId){
  try{stagedImports=stagedImports.filter(job=>job.import_id!==importId);await syncPreparationSession();const response=await fetch('/api/import/'+encodeURIComponent(importId),{method:'DELETE'});const body=await response.json();if(!response.ok)throw Error(apiErrorMessage(body,'Import could not be removed'));renderImportWorkspace();setStatus('Staged import removed.');}catch(error){setStatus(error.message,true);}
}

async function clearImports(){for(const job of [...stagedImports])await removeImport(job.import_id);}

function assessmentBuildRequest(action){
  if(preparationSession)return {session_id:preparationSession.session_id,action};
  const local=el('build-as-of').value;const asOf=local?new Date(local).toISOString():null;
  return {import_ids:stagedImports.map(job=>job.import_id),scope:el('build-scope').value.trim(),as_of:asOf,synthetic:el('build-synthetic').checked,action};
}

function preparationValues(){
  const local=el('build-as-of').value;
  return {import_ids:stagedImports.map(job=>job.import_id),scope:el('build-scope').value.trim(),
          as_of:local?new Date(local).toISOString():null,synthetic:el('build-synthetic').checked};
}

async function createPreparationSession(){
  const response=await fetch('/api/preparation',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});const body=await response.json();
  if(!response.ok)throw Error(apiErrorMessage(body,'Preparation session could not be created'));preparationSession=body;return body;
}

async function syncPreparationSession(){
  try{
    if(!preparationSession)await createPreparationSession();
    const response=await fetch('/api/preparation/'+encodeURIComponent(preparationSession.session_id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(preparationValues())});const body=await response.json();
    if(!response.ok)throw Error(apiErrorMessage(body,'Preparation session could not be saved'));preparationSession=body;
    if(body.coverage)renderCoverage(body.coverage);buildReady=body.status==='ready';el('run-import-assessment').disabled=!buildReady;
    if(body.correlation_readiness&&body.correlation_readiness!=='not_evaluated')el('build-message').textContent=`Preparation saved · correlation ${title(body.correlation_readiness)}`;
  }catch(error){setStatus(error.message,true);}
}

async function loadPreparationSession(){
  try{
    const response=await fetch('/api/preparation/latest');
    if(response.status===404){await createPreparationSession();return;}
    const body=await response.json();if(!response.ok)throw Error(apiErrorMessage(body,'Preparation session could not be restored'));preparationSession=body;
    el('build-scope').value=body.scope||'';el('build-synthetic').checked=body.synthetic===true;
    if(body.as_of){const value=new Date(body.as_of);if(!Number.isNaN(value.getTime())){value.setMinutes(value.getMinutes()-value.getTimezoneOffset());el('build-as-of').value=value.toISOString().slice(0,16);}}
    const restored=await Promise.all((body.import_ids||[]).map(id=>fetchJson('/api/import/'+encodeURIComponent(id),'A staged import could not be restored')));stagedImports=restored;renderImportWorkspace();
    if(body.coverage)renderCoverage(body.coverage);buildReady=body.status==='ready';el('run-import-assessment').disabled=!buildReady;setStatus('Preparation session restored.');
  }catch(error){setStatus(error.message,true);}
}

async function requestAssessmentBuild(action){
  const response=await fetch('/api/assessment-build',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(assessmentBuildRequest(action))});let body;
  try{body=await response.json();}catch(error){throw Error('Assessment build response was not valid JSON');}
  if(!response.ok)throw Error(apiErrorMessage(body,'Assessment build failed'));return {body,response};
}

async function previewAssessmentBuild(){
  try{setStatus('Checking combined evidence…');await syncPreparationSession();const {body}=await requestAssessmentBuild('preview');renderCoverage(body.coverage);buildReady=body.ready===true;el('run-import-assessment').disabled=!buildReady;const correlation=body.correlation&&body.correlation.status;el('build-message').textContent=buildReady?`All required evidence is valid${correlation?` · correlation ${title(correlation)}`:''}.`:`Evidence is incomplete${body.missing_categories&&body.missing_categories.length?`: ${body.missing_categories.map(title).join(', ')}`:'.'}`;setStatus(buildReady?'Combined evidence is ready for assessment.':'Combined evidence needs attention.',!buildReady);}catch(error){buildReady=false;el('run-import-assessment').disabled=true;setStatus(error.message,true);el('build-message').textContent=error.message;}
}

async function runImportedAssessment(){
  try{setStatus('Running assessment from mapped evidence…');await syncPreparationSession();const {body,response}=await requestAssessmentBuild('assess');historyCache.delete(body.scope);mode='import';setAssessment(body,response.headers.get('X-Assessment-ID'));preparationSession=null;stagedImports=[];renderImportWorkspace();await createPreparationSession();window.location.hash='#assessments';setStatus('Imported evidence assessed and stored locally.');}catch(error){setStatus(error.message,true);}
}

function attachEvents(){
  window.addEventListener('hashchange',applyRoute);
  el('menu-toggle').addEventListener('click',toggleNavigation);
  el('baseline').addEventListener('click',()=>{if(demo){mode='baseline';setAssessment(demo.baseline,demo.assessment_ids&&demo.assessment_ids.baseline);}});
  el('degraded').addEventListener('click',()=>{if(demo){mode='degraded';setAssessment(demo.degraded,demo.assessment_ids&&demo.assessment_ids.degraded);}});
  el('import-profile').addEventListener('change',renderMappingProfile);
  el('stage-import').addEventListener('click',stageImport);
  el('clear-imports').addEventListener('click',clearImports);
  el('preview-build').addEventListener('click',previewAssessmentBuild);
  el('run-import-assessment').addEventListener('click',runImportedAssessment);
  for(const id of ['build-scope','build-as-of','build-synthetic'])el(id).addEventListener('change',async()=>{renderLocalCoverage();await syncPreparationSession();});
  el('download').addEventListener('click',downloadReport);
  el('download-audit').addEventListener('click',downloadAudit);
  el('history-compare').addEventListener('click',runHistoryComparison);
  document.addEventListener('keydown',event=>{if(event.key==='Escape')closeNavigation();});
  document.addEventListener('click',event=>{
    if(document.body.classList.contains('nav-open')&&!el('sidebar').contains(event.target)&&!el('menu-toggle').contains(event.target))closeNavigation();
  });
}

async function loadDemo(){
  try{
    demo=await fetchJson('/api/demo','Demonstration assessment could not be loaded');mode='baseline';setAssessment(demo.baseline,demo.assessment_ids&&demo.assessment_ids.baseline);
  }catch(error){setStatus(error.message,true);renderNoAssessment(currentRoute());}
}

function init(){
  attachEvents();applyRoute();loadServiceStatus();loadImportProfiles();renderImportWorkspace();
  const now=new Date();now.setMinutes(now.getMinutes()-now.getTimezoneOffset());el('build-as-of').value=now.toISOString().slice(0,16);
  loadPreparationSession();loadDemo();
}

init();
