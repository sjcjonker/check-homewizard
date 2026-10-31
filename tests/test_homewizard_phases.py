"""Combined phase checks and stable archive identity, without device requests."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

hw = load('phase_plugin', 'check_homewizard.py')

class CombinedPhases(unittest.TestCase):
    def test_voltage_uses_worst_phase_and_retains_thresholds_in_perfdata(self):
        args = SimpleNamespace(phase_type='voltage', timeout=5, max_age=180,
                               warning='218.5:241.5', critical='207:253')
        data = dict(voltage_l1_v=230, voltage_l2_v=242, voltage_l3_v=254)
        with mock.patch.object(hw, 'measurement', return_value=data) as request, \
             mock.patch.object(hw, 'ensure_fresh'):
            code, message, perf = hw.phases_check(dict(kind='p1', api=2), args)
        self.assertEqual(code, 2)
        self.assertIn('L2=242 V (WARNING)', message)
        self.assertIn('L3=254 V (CRITICAL)', message)
        self.assertIn('voltage_l1_v', perf)
        self.assertEqual(perf.count(';218.5:241.5;207:253;'), 3)
        request.assert_called_once()


    def test_missing_phase_is_unknown_and_stale_data_is_rejected(self):
        args = SimpleNamespace(phase_type='voltage', timeout=5, max_age=180,
                               warning=None, critical=None)
        with mock.patch.object(hw, 'measurement', return_value={'voltage_l1_v': 230}), \
             mock.patch.object(hw, 'ensure_fresh'):
            with self.assertRaises(hw.CheckError):
                hw.phases_check(dict(kind='p1', api=2), args)
        with mock.patch.object(hw, 'measurement', return_value={}), \
             mock.patch.object(hw, 'ensure_fresh', side_effect=hw.CheckError('stale')):
            with self.assertRaisesRegex(hw.CheckError, 'stale'):
                hw.phases_check(dict(kind='p1', api=2), args)
