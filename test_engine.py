import copy
import json
import unittest
from pathlib import Path
from engine import assess, compare, normalize

class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((Path(__file__).parent/'data/baseline.json').read_text())
        self.data.pop('lifecycles',None)
    def test_hand_calculated_detection(self):
        self.assertEqual(assess(self.data)['domains']['Detection'],70.0)
    def test_response_denominator_excludes_false_positive(self):
        r=assess(self.data)
        self.assertEqual(r['counts']['response_denominator'],20)
        self.assertEqual(r['domains']['Response'],75.0)
    def test_empty_evidence_is_provisional(self):
        for k in ['sources','techniques','cases','controls']:self.data[k]=[]
        r=assess(self.data)
        self.assertEqual((r['score'],r['confidence'],r['maturity']),(0,0,'Provisional'))
    def test_untested_never_earns_coverage(self):
        for t in self.data['techniques']:t['status']='untested'
        self.assertEqual(assess(self.data)['domains']['Detection'],0)
    def test_missing_test_reference_receives_zero(self):
        self.data['techniques'][0]['evidence_ref']=''
        self.assertLess(assess(self.data)['domains']['Detection'],70)
    def test_stale_test_receives_zero(self):
        self.data['techniques'][0]['tested_at']='2026-01-01T00:00:00+00:00'
        self.assertLess(assess(self.data)['domains']['Detection'],70)
    def test_absent_containment_counts_as_miss(self):
        self.data['cases'][0]['contained_at']=None
        self.assertEqual(assess(self.data)['domains']['Response'],70)
    def test_critical_gap_caps_level(self):
        self.data['controls'][0]['satisfied']=False
        self.assertEqual(assess(self.data)['maturity'],'L2')
    def test_low_sample_gate(self):
        self.data['cases']=self.data['cases'][:5]
        self.assertEqual(assess(self.data)['maturity'],'Provisional')
    def test_duplicate_id_rejected(self):
        self.data['cases'][1]['id']=self.data['cases'][0]['id']
        with self.assertRaises(ValueError):assess(self.data)
    def test_future_timestamp_rejected(self):
        self.data['sources'][0]['last_seen']='2027-01-01T00:00:00+00:00'
        with self.assertRaises(ValueError):assess(self.data)
    def test_nan_rejected(self):
        self.data['sources'][0]['completeness']=float('nan')
        with self.assertRaises(ValueError):assess(self.data)
    def test_unknown_source_rejected(self):
        self.data['techniques'][0]['source_id']='unknown'
        with self.assertRaises(ValueError):assess(self.data)
    def test_negative_duration_rejected(self):
        self.data['cases'][0]['contained_at']='2020-01-01T00:00:00+00:00'
        with self.assertRaises(ValueError):assess(self.data)
    def test_reproducible_hash(self):
        self.assertEqual(assess(self.data)['sha256'],assess(copy.deepcopy(self.data))['sha256'])
    def test_scope_change_blocks_comparison(self):
        before=assess(self.data)
        self.data['techniques'][0]['risk_weight']=1
        with self.assertRaises(ValueError):compare(before,assess(self.data))
    def test_degradation_triggers_drift(self):
        degraded=json.loads((Path(__file__).parent/'data/degraded.json').read_text())
        degraded.pop('lifecycles',None)
        self.assertTrue(compare(assess(self.data),assess(degraded))['drift_alert'])

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((Path(__file__).parent/'data/baseline.json').read_text())

    def lifecycle_findings(self, report, stage):
        return [f for f in report['findings'] if f.get('stage')==stage]

    def test_valid_complete_lifecycle(self):
        lifecycle=assess(self.data)['lifecycle']
        self.assertTrue(lifecycle['enabled'])
        self.assertEqual((lifecycle['incident_count'],lifecycle['complete_incidents']),(6,6))
        self.assertFalse(any(f.get('incident_id') for f in assess(self.data)['findings']))

    def test_alert_without_investigation(self):
        self.data['lifecycles'][0]['investigation']=None
        report=assess(self.data)
        finding=self.lifecycle_findings(report,'investigation')[0]
        self.assertEqual((finding['incident_id'],finding['alert_id'],finding['case_id']),('INC-001','ALERT-001','CASE-001'))
        self.assertEqual(finding['evidence_ref'],'demo://lifecycle/INC-001/detection')

    def test_required_escalation_missing(self):
        self.data['lifecycles'][0]['escalation']=None
        finding=self.lifecycle_findings(assess(self.data),'escalation')[0]
        self.assertEqual((finding['incident_id'],finding['stage']),('INC-001','escalation'))

    def test_response_missing(self):
        self.data['lifecycles'][0]['response']=None
        finding=self.lifecycle_findings(assess(self.data),'response')[0]
        self.assertEqual((finding['incident_id'],finding['stage']),('INC-001','response'))

    def test_closure_missing(self):
        self.data['lifecycles'][0]['closure']=None
        finding=self.lifecycle_findings(assess(self.data),'closure')[0]
        self.assertEqual((finding['incident_id'],finding['stage']),('INC-001','closure'))

    def test_correct_lifecycle_correlation(self):
        _,normalized=normalize(self.data)
        incident=normalized['incidents'][0]
        self.assertEqual((incident['source_id'],incident['alert_id'],incident['case_id'],incident['incident_id']),('siem-1','ALERT-001','CASE-001','INC-001'))

    def test_lifecycle_timing_calculation(self):
        incident=assess(self.data)['lifecycle']['incidents'][0]
        self.assertEqual(incident['timing_minutes'],{
            'detection_to_investigation':5.0,
            'investigation_to_escalation':5.0,
            'escalation_to_response':20.0,
            'response_to_closure':60.0,
            'total_lifecycle':90.0,
        })

    def test_lifecycle_addition_changes_input_sha(self):
        lifecycle_sha=assess(self.data)['sha256']
        legacy=copy.deepcopy(self.data)
        legacy.pop('lifecycles')
        self.assertEqual(assess(legacy)['sha256'],'1823b55bc5698ea3632221dc476fb456f0764b56147ee7bf065f29f2a46cfd58')
        self.assertNotEqual(lifecycle_sha,assess(legacy)['sha256'])

    def test_lifecycle_timestamp_changes_input_sha(self):
        before=assess(self.data)['sha256']
        self.data['lifecycles'][0]['investigation']['timestamp']='2026-09-28T12:06:00+00:00'
        self.assertNotEqual(before,assess(self.data)['sha256'])

    def test_lifecycle_evidence_ref_changes_input_sha(self):
        before=assess(self.data)['sha256']
        self.data['lifecycles'][0]['investigation']['evidence_ref']='demo://changed-reference'
        self.assertNotEqual(before,assess(self.data)['sha256'])

    def test_lifecycle_identifiers_policy_and_status_change_input_sha(self):
        before=assess(self.data)['sha256']
        changes=(
            ('incident_id','INC-CHANGED'),
            ('alert_id','ALERT-CHANGED'),
            ('source_id','edr-1'),
            ('escalation_required',False),
        )
        for field,value in changes:
            with self.subTest(field=field):
                data=copy.deepcopy(self.data)
                data['lifecycles'][0][field]=value
                self.assertNotEqual(before,assess(data)['sha256'])
        status=copy.deepcopy(self.data)
        status['lifecycles'][0]['investigation']['status']='reviewed'
        self.assertNotEqual(before,assess(status)['sha256'])
        case_base=copy.deepcopy(self.data)
        alias=copy.deepcopy(case_base['cases'][0])
        alias['id']='CASE-ALIAS'
        case_base['cases'].append(alias)
        case_changed=copy.deepcopy(case_base)
        case_changed['lifecycles'][0]['case_id']='CASE-ALIAS'
        self.assertNotEqual(assess(case_base)['sha256'],assess(case_changed)['sha256'])

    def test_scope_hash_covers_correlations_not_operational_results(self):
        before=assess(self.data)['scope_sha256']
        operational=copy.deepcopy(self.data)
        operational['lifecycles'][0]['investigation']['timestamp']='2026-09-28T12:06:00+00:00'
        operational['lifecycles'][0]['investigation']['evidence_ref']='demo://changed-reference'
        operational['lifecycles'][0]['investigation']['status']='reviewed'
        self.assertEqual(before,assess(operational)['scope_sha256'])
        correlation=copy.deepcopy(self.data)
        correlation['lifecycles'][0]['incident_id']='INC-CHANGED'
        self.assertNotEqual(before,assess(correlation)['scope_sha256'])

    def test_inconsistent_lifecycle_case_timestamps_are_rejected(self):
        changes=(
            ('detection','2026-09-28T12:01:00+00:00'),
            ('response','2026-09-28T12:29:00+00:00'),
            ('response','2026-09-28T12:31:00+00:00'),
        )
        for stage,value in changes:
            with self.subTest(stage=stage,value=value):
                data=copy.deepcopy(self.data)
                data['lifecycles'][0][stage]['timestamp']=value
                with self.assertRaises(ValueError):assess(data)

    def test_valid_consistent_lifecycle_timestamps_pass(self):
        assess(self.data)
        initial_response=copy.deepcopy(self.data)
        initial_response['lifecycles'][0]['response']['timestamp']='2026-09-28T12:20:00+00:00'
        initial_response['lifecycles'][0]['response']['status']='started'
        self.assertEqual(assess(initial_response)['lifecycle']['incident_count'],6)

    def test_invalid_correlation_ids(self):
        changes=(('source_id','unknown-source'),('case_id','unknown-case'))
        for field,value in changes:
            with self.subTest(field=field):
                data=copy.deepcopy(self.data)
                data['lifecycles'][0][field]=value
                with self.assertRaises(ValueError):assess(data)
        duplicate=copy.deepcopy(self.data)
        duplicate['lifecycles'][1]['alert_id']=duplicate['lifecycles'][0]['alert_id']
        with self.assertRaises(ValueError):assess(duplicate)

    def test_original_json_format_remains_compatible(self):
        self.data.pop('lifecycles')
        report=assess(self.data)
        self.assertEqual((report['score'],report['confidence'],report['maturity']),(80.2,94.4,'L3'))
        self.assertEqual(report['sha256'],'1823b55bc5698ea3632221dc476fb456f0764b56147ee7bf065f29f2a46cfd58')
        self.assertEqual((report['lifecycle']['enabled'],report['lifecycle']['incident_count']),(False,0))

class LifecycleScoringTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((Path(__file__).parent/'data/baseline.json').read_text())

    def test_complete_timely_lifecycle_receives_full_credit(self):
        scoring=assess(self.data)['lifecycle']['scoring']
        self.assertEqual(scoring['operational_response']['score'],100.0)
        self.assertEqual(scoring['closure_discipline']['score'],100.0)
        self.assertTrue(all(component['score']==100.0 for component in scoring['components'].values()))

    def test_delayed_investigation_reduces_response(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['investigation']['timestamp']='2026-09-28T12:16:00+00:00'
        self.data['lifecycles'][0]['escalation']['timestamp']='2026-09-28T12:20:00+00:00'
        after=assess(self.data)
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['investigation']['delayed'],1)

    def test_missing_investigation_reduces_response(self):
        before=assess(self.data)
        self.data['lifecycles'][1]['investigation']=None
        after=assess(self.data)
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['investigation']['missing'],1)

    def test_missing_required_escalation_reduces_response(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['escalation']=None
        after=assess(self.data)
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['escalation']['missing'],1)

    def test_escalation_not_required_does_not_penalize(self):
        before=assess(self.data)
        self.assertEqual(before['lifecycle']['scoring']['components']['escalation']['not_applicable'],3)
        self.data['lifecycles'][1]['escalation']={
            'timestamp':'2026-09-28T11:10:00+00:00',
            'evidence_ref':'demo://lifecycle/INC-002/escalation',
            'status':'recorded',
        }
        after=assess(self.data)
        self.assertEqual(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['escalation']['applicable'],3)

    def test_delayed_escalation_reduces_response(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['escalation']['timestamp']='2026-09-28T12:21:00+00:00'
        after=assess(self.data)
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['escalation']['delayed'],1)

    def test_missing_response_reduces_response(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['response']=None
        after=assess(self.data)
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual(after['lifecycle']['scoring']['components']['response']['missing'],1)

    def test_delayed_response_reduces_response_and_is_explainable(self):
        before=assess(self.data)
        self.data['cases'][0]['sla_minutes']=90
        self.data['cases'][0]['contained_at']='2026-09-28T13:15:00+00:00'
        self.data['lifecycles'][0]['response']['timestamp']='2026-09-28T13:15:00+00:00'
        after=assess(self.data)
        finding=[f for f in after['findings'] if f.get('incident_id')=='INC-001' and f.get('stage')=='response'][0]
        self.assertLess(after['domains']['Response'],before['domains']['Response'])
        self.assertEqual((finding['finding_type'],finding['observed_minutes'],finding['policy_threshold_minutes']),('delayed',75.0,60))

    def test_missing_closure_reduces_quality(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['closure']=None
        after=assess(self.data)
        self.assertEqual(after['domains']['Response'],before['domains']['Response'])
        self.assertLess(after['domains']['Quality'],before['domains']['Quality'])
        self.assertEqual(after['lifecycle']['scoring']['components']['closure']['missing'],1)

    def test_delayed_closure_reduces_quality_and_is_explainable(self):
        before=assess(self.data)
        self.data['lifecycles'][0]['closure']['timestamp']='2026-09-28T16:31:00+00:00'
        after=assess(self.data)
        finding=[f for f in after['findings'] if f.get('incident_id')=='INC-001' and f.get('stage')=='closure'][0]
        self.assertLess(after['domains']['Quality'],before['domains']['Quality'])
        self.assertEqual((finding['finding_type'],finding['observed_minutes'],finding['policy_threshold_minutes']),('delayed',241.0,240))

    def test_lifecycle_timing_boundaries(self):
        cases=[]
        investigation=copy.deepcopy(self.data)
        investigation['lifecycles'][0]['investigation']['timestamp']='2026-09-28T12:15:00+00:00'
        investigation['lifecycles'][0]['escalation']['timestamp']='2026-09-28T12:20:00+00:00'
        cases.append((investigation,'investigation','timely'))
        escalation=copy.deepcopy(self.data)
        escalation['lifecycles'][0]['escalation']['timestamp']='2026-09-28T12:20:00+00:00'
        cases.append((escalation,'escalation','timely'))
        response=copy.deepcopy(self.data)
        response['cases'][0]['contained_at']='2026-09-28T13:00:00+00:00'
        response['lifecycles'][0]['response']['timestamp']='2026-09-28T13:00:00+00:00'
        cases.append((response,'response','timely'))
        closure=copy.deepcopy(self.data)
        closure['lifecycles'][0]['closure']['timestamp']='2026-09-28T16:30:00+00:00'
        cases.append((closure,'closure','timely'))
        response_late=copy.deepcopy(response)
        response_late['cases'][0]['contained_at']='2026-09-28T13:01:00+00:00'
        response_late['lifecycles'][0]['response']['timestamp']='2026-09-28T13:01:00+00:00'
        cases.append((response_late,'response','delayed'))
        closure_late=copy.deepcopy(self.data)
        closure_late['lifecycles'][0]['closure']['timestamp']='2026-09-28T16:31:00+00:00'
        cases.append((closure_late,'closure','delayed'))
        for data,stage,expected in cases:
            with self.subTest(stage=stage,expected=expected):
                evaluation=assess(data)['lifecycle']['incidents'][0]['stage_evaluation'][stage]
                self.assertEqual(evaluation['result'],expected)

    def test_lifecycle_scoring_explanation_is_consistent(self):
        report=assess(self.data)
        scoring=report['lifecycle']['scoring']
        components=scoring['components']
        for component in components.values():
            self.assertEqual(component['applicable'],component['timely']+component['delayed']+component['missing']+component['unmeasured'])
        operational=scoring['operational_response']
        self.assertEqual(operational['applicable'],sum(components[name]['applicable'] for name in ('investigation','escalation','response')))
        self.assertEqual(operational['credits'],sum(components[name]['credits'] for name in ('investigation','escalation','response')))
        for domain in ('Response','Quality'):
            impact=scoring['domain_impact'][domain]
            calculated=100*(impact['legacy_credits']+impact['lifecycle_credits'])/(impact['legacy_requirements']+impact['lifecycle_requirements'])
            self.assertEqual(impact['combined_score'],round(calculated,1))
            self.assertEqual(impact['combined_score'],report['domains'][domain])

    def test_degraded_demo_loses_score_from_lifecycle_failures(self):
        degraded=json.loads((Path(__file__).parent/'data/degraded.json').read_text())
        full=assess(degraded)
        legacy=copy.deepcopy(degraded)
        legacy.pop('lifecycles')
        legacy_report=assess(legacy)
        self.assertLess(full['domains']['Response'],legacy_report['domains']['Response'])
        self.assertLess(full['domains']['Quality'],legacy_report['domains']['Quality'])
        self.assertLess(full['score'],legacy_report['score'])

    def test_confidence_distinguishes_traceability_from_performance(self):
        before=assess(self.data)
        poor_performance=copy.deepcopy(self.data)
        poor_performance['lifecycles'][1]['investigation']=None
        poor_performance['lifecycles'][1]['closure']=None
        poor=assess(poor_performance)
        self.assertLess(poor['score'],before['score'])
        self.assertEqual(poor['confidence'],before['confidence'])
        untraceable=copy.deepcopy(self.data)
        untraceable['lifecycles'][0]['investigation']['evidence_ref']=''
        self.assertLess(assess(untraceable)['confidence'],before['confidence'])

if __name__=='__main__':unittest.main()
