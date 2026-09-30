import copy
import json
import unittest
from pathlib import Path
from engine import assess, compare

class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.data=json.loads((Path(__file__).parent/'data/baseline.json').read_text())
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
        self.assertTrue(compare(assess(self.data),assess(degraded))['drift_alert'])

if __name__=='__main__':unittest.main()
