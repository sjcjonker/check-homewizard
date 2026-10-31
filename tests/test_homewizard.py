"""Offline HomeWizard regression tests; all network fixtures are loopback only."""
import contextlib
import datetime as dt
from decimal import Decimal
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('homewizard', ROOT / 'check_homewizard.py')
hw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hw)


def args(**overrides):
    values = dict(warning='0.5', critical='1', min_interval=750, max_gap=1800, window_seconds=900, rate_thresholds=False,
                  timeout=2, max_age=180, metric='power_w')
    values.update(overrides)
    return SimpleNamespace(**values)


def p1(**overrides):
    config = dict(address='127.0.0.1', api=2, kind='p1', serial='001122334455',
                  token='A' * 32, timezone='Europe/Amsterdam')
    config.update(overrides)
    return config


def sample(imported='100', exported='20', **fields):
    data = dict(energy_import_kwh=imported, unique_id='smart-meter-1', power_w='123.456')
    if exported is not None:
        data['energy_export_kwh'] = exported
    data.update(fields)
    return data


class Calculations(unittest.TestCase):
    def test_voltage_boundaries_and_decimal_values(self):
        for voltage, expected in [('207', 1), ('206.99', 2), ('218.5', 0),
                                  ('241.5', 0), ('241.51', 1), ('253', 1), ('253.01', 2)]:
            self.assertEqual(hw.status(Decimal(voltage), '218.5:241.5', '207:253'), expected)
        self.assertEqual(hw.fmt('241.5'), '241.5')

    def test_frequency_thresholds(self):
        for hz, expected in [('47.99', 2), ('48', 1), ('49', 0), ('50.01', 0),
                             ('51', 0), ('52', 1), ('52.01', 2)]:
            self.assertEqual(hw.status(Decimal(hz), '49:51', '48:52'), expected)

    def test_negative_export_and_nagios_ranges(self):
        self.assertEqual(hw.status(-5000, '~:5500', '~:7500'), 0)
        self.assertEqual(hw.status(5501, '~:5500', '~:7500'), 1)
        self.assertEqual(hw.status(7501, '~:5500', '~:7500'), 2)
        self.assertTrue(hw.outside(5, '@1:5'))
        self.assertFalse(hw.outside(6, '@1:5'))
        self.assertFalse(hw.outside(-10, '~:0'))
        with self.assertRaises(hw.CheckError):
            hw.outside(10, '20:10')

    def test_rssi_low_values_alert(self):
        for rssi, expected in [(-65, 0), (-75, 1), (-85, 2)]:
            self.assertEqual(hw.status(rssi, '-70:0', '-80:0'), expected)

    def test_invalid_missing_and_nonfinite_values(self):
        for value in [True, False, None, 'NaN', 'Infinity', {}, 'bad']:
            with self.subTest(value=value), self.assertRaises(hw.CheckError):
                hw.number(value)
        with self.assertRaises(hw.CheckError):
            hw.metric_value(p1(), {}, 'current_l2_a')

    def test_water_conversion_and_flow(self):
        config = p1(kind='water', api=1)
        self.assertEqual(hw.metric_value(config, {'total_liter_m3': '123.456'}, 'water_total_l'), Decimal('123456'))
        self.assertEqual(hw.metric_value(config, {'active_liter_lpm': '7.2'}, 'flow_lpm'), Decimal('7.2'))

    def test_v1_p1_mapping(self):
        config = p1(api=1)
        self.assertEqual(hw.metric_value(config, {'active_frequency_hz': '49.99'}, 'frequency_hz'), Decimal('49.99'))
        self.assertEqual(hw.metric_value(config, {'total_power_import_kwh': '10'}, 'energy_import_kwh'), Decimal(10))

    def test_standard_performance_data_units(self):
        with mock.patch.object(hw, 'measurement', return_value={'voltage_l1_v': '241.5'}):
            result = hw.metric_check(p1(), args(metric='voltage_l1_v', warning='218.5:241.5', critical='207:253'))
        self.assertEqual(result[0], 0)
        self.assertIn("'voltage_l1_v'=241.5;218.5:241.5;207:253;;", result[2])
        self.assertNotIn('241.5V', result[2])

    def test_optional_export_not_assumed_zero(self):
        baseline, _ = hw.usage_sample(p1(), sample(exported=None), None, 1000, args())
        _, result = hw.usage_sample(p1(), sample('100.6', None), baseline, 1900, args())
        self.assertEqual(result[0], 1)
        self.assertIn('export counter unavailable', result[1])
        self.assertNotIn('export_kWh', result[2])

    def test_missing_import_counter_is_unknown(self):
        with self.assertRaises(hw.CheckError):
            hw.usage_sample(p1(), {'power_w': 0}, None, 1000, args())

    def test_baseline_then_import_export_deltas(self):
        baseline, result = hw.usage_sample(p1(), sample(), None, 1000, args())
        self.assertEqual(result[0], 3)
        state, result = hw.usage_sample(p1(), sample('100.6', '20.1'), baseline, 1900, args())
        self.assertEqual(result[0], 1)
        self.assertIn('0.6 kWh over 15 min', result[1])
        self.assertIn("'average_import_w'=2400", result[2])
        self.assertIn("'export_kWh_interval'=0.1", result[2])
        self.assertEqual(state['time'], 1900)

    def test_actual_elapsed_time_normalizes_threshold(self):
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, args())
        _, result = hw.usage_sample(p1(), sample('100.6'), baseline, 2080, args())
        self.assertEqual(result[0], 0)  # 0.6 over 18 min = exactly 0.5 per 15 min
        self.assertIn('0.5 kWh/15min', result[1])

    def test_water_100_litre_boundary_and_critical(self):
        config, options = p1(kind='water', api=1), args(warning='100', critical='200')
        baseline, _ = hw.usage_sample(config, {'total_liter_m3': '10'}, None, 1000, options)
        for total, expected in [('10.100', 0), ('10.101', 1), ('10.201', 2)]:
            _, result = hw.usage_sample(config, {'total_liter_m3': total}, baseline, 1900, options)
            self.assertEqual(result[0], expected)
        _, result = hw.usage_sample(config, {'total_liter_m3': '10.120'}, baseline, 1900, options)
        self.assertIn("'average_flow_lpm'=8", result[2])

    def test_five_minute_water_usage_normalizes_elapsed_time(self):
        config = p1(kind='water', api=1)
        options = args(warning='55', critical='80', min_interval=240,
                       max_gap=600, window_seconds=300)
        baseline, _ = hw.usage_sample(config, {'total_liter_m3': '10'}, None, 1000, options)
        _, ok = hw.usage_sample(config, {'total_liter_m3': '10.055'}, baseline, 1300, options)
        self.assertEqual(ok[0], 0)
        self.assertIn('55 L/5min', ok[1])
        self.assertIn("'water_L_5m'=55", ok[2])
        _, warning = hw.usage_sample(config, {'total_liter_m3': '10.056'}, baseline, 1300, options)
        self.assertEqual(warning[0], 1)
        _, critical = hw.usage_sample(config, {'total_liter_m3': '10.081'}, baseline, 1300, options)
        self.assertEqual(critical[0], 2)
        _, normalized = hw.usage_sample(config, {'total_liter_m3': '10.066'}, baseline, 1360, options)
        self.assertEqual(normalized[0], 0)  # 66 L in 6 min = 55 L per 5 min

    def test_average_rate_thresholds(self):
        water = args(warning='15', critical='20', min_interval=240, max_gap=600,
                     window_seconds=300, rate_thresholds=True)
        config = p1(kind='water', api=1)
        baseline, _ = hw.usage_sample(config, {'total_liter_m3': '10'}, None, 1000, water)
        for total, expected in [('10.075', 0), ('10.076', 1), ('10.101', 2)]:
            _, result = hw.usage_sample(config, {'total_liter_m3': total}, baseline, 1300, water)
            self.assertEqual(result[0], expected)
        power = args(warning='5.5', critical='7', rate_thresholds=True)
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, power)
        for total, expected in [('101.375', 0), ('101.376', 1), ('101.750', 1), ('101.751', 2)]:
            _, result = hw.usage_sample(p1(), sample(total), baseline, 1900, power)
            self.assertEqual(result[0], expected)

    def test_retry_does_not_clear_warning_or_advance_baseline(self):
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, args())
        state, result = hw.usage_sample(p1(), sample('100.6'), baseline, 1900, args())
        repeated, retry = hw.usage_sample(p1(), sample('100.601'), state, 1960, args())
        self.assertIs(repeated, state)
        self.assertEqual(retry[0], result[0])
        self.assertIn('previous interval retained', retry[1])
        self.assertEqual(retry[2], result[2])

    def test_threshold_change_applies_to_cached_interval(self):
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, args())
        state, _ = hw.usage_sample(p1(), sample('100.6'), baseline, 1900, args())
        _, result = hw.usage_sample(p1(), sample('100.601'), state, 1960, args(warning='0.7'))
        self.assertEqual(result[0], 0)

    def test_too_early_second_sample_remains_unknown(self):
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, args())
        same, result = hw.usage_sample(p1(), sample('100.1'), baseline, 1600, args())
        self.assertIs(same, baseline)
        self.assertEqual(result[0], 3)

    def test_counter_reset_identity_change_and_excessive_gap(self):
        baseline, _ = hw.usage_sample(p1(), sample(), None, 1000, args())
        for data, now in [(sample('0'), 1900), (sample(unique_id='replacement'), 1900),
                          (sample(), 2801), (sample(), 999), (sample(exported=None), 1900)]:
            with self.subTest(data=data, now=now):
                state, result = hw.usage_sample(p1(), data, baseline, now, args())
                self.assertEqual(result[0], 3)
                self.assertNotIn('result', state)

    def test_negative_counters_rejected(self):
        with self.assertRaises(hw.CheckError):
            hw.usage_sample(p1(), sample('-1'), None, 1000, args())

    def test_freshness_local_timezone_stale_and_future(self):
        now = dt.datetime(2026, 10, 12, 10, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(hw.freshness({'timestamp': '2026-10-12T11:59:30'}, 'Europe/Amsterdam', now), 30)
        self.assertIsNone(hw.freshness({}, 'Europe/Amsterdam', now))
        with self.assertRaises(hw.CheckError):
            hw.freshness({'timestamp': '2026-10-12T12:03:00'}, 'Europe/Amsterdam', now)
        with mock.patch.object(hw, 'freshness', return_value=181):
            with self.assertRaises(hw.CheckError) as caught:
                hw.ensure_fresh({}, p1(), 180)
            self.assertEqual(caught.exception.code, 2)

    def test_dst_fold_uses_nearest_instant(self):
        now = dt.datetime(2026, 10, 25, 1, 30, tzinfo=dt.timezone.utc)
        self.assertEqual(hw.freshness({'timestamp': '2026-10-25T02:29:30'}, 'Europe/Amsterdam', now), 30)


class FilesAndChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.config = p1(state_dir=str(self.directory))

    def tearDown(self):
        self.temporary.cleanup()

    def test_simultaneous_checks_share_one_request(self):
        results, failures = [], []
        start = threading.Barrier(8)
        def run():
            try:
                start.wait()
                results.append(hw.request(self.config, '/api/measurement', 2))
            except Exception as error:
                failures.append(error)
        with mock.patch.object(hw, 'network_request', return_value=sample()) as network:
            workers = [threading.Thread(target=run) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
            self.assertFalse(any(worker.is_alive() for worker in workers))
            network.assert_called_once()
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 8)
        self.assertTrue(all(hw.value(result, 'power_w') == Decimal('123.456') for result in results))

    def test_cache_expiry_does_not_mask_connection_failure(self):
        with mock.patch.object(hw.time, 'monotonic', return_value=1000), mock.patch.object(hw, 'network_request', return_value=sample()):
            hw.request(self.config, '/api/measurement', 2)
        path = self.directory / '001122334455.request-cache.json'
        original = path.read_bytes()
        with mock.patch.object(hw.time, 'monotonic', return_value=1011), mock.patch.object(hw, 'network_request', side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):
                hw.request(self.config, '/api/measurement', 2)
        self.assertEqual(path.read_bytes(), original)

    def test_cache_keeps_endpoints_and_credentials_separate(self):
        with mock.patch.object(hw, 'network_request', return_value=sample()) as network:
            hw.request(self.config, '/api/measurement', 2)
            hw.request(self.config, '/api/system', 2)
            hw.request(self.config, '/api/measurement', 2)
            self.assertEqual(network.call_count, 2)
            hw.request({**self.config, 'token': 'B' * 32}, '/api/measurement', 2)
            self.assertEqual(network.call_count, 3)
        content = (self.directory / '001122334455.request-cache.json').read_text()
        self.assertNotIn('A' * 32, content)
        self.assertNotIn('B' * 32, content)

    def test_pairing_and_verification_bypass_cache(self):
        with mock.patch.object(hw, 'network_request', return_value=sample()) as network:
            hw.request(self.config, '/api/user', 2, method='POST', body={'name': 'local/nagios'}, pairing=True)
            hw.request(self.config, '/api', 2, cache=False)
            self.assertEqual(network.call_count, 2)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_corrupt_request_cache_is_replaced_without_usage_reset(self):
        path = self.directory / '001122334455.request-cache.json'
        path.write_text('bad JSON')
        baseline = self.directory / '001122334455.json'
        baseline.write_text('usage baseline untouched')
        with mock.patch.object(hw, 'network_request', return_value=sample()):
            self.assertEqual(hw.request(self.config, '/api/measurement', 2), sample())
        self.assertIsInstance(json.loads(path.read_text()), dict)
        self.assertEqual(baseline.read_text(), 'usage baseline untouched')

    def test_atomic_state_permissions_and_corruption_recovery(self):
        options = args()
        with mock.patch.object(hw, 'measurement', return_value=sample()), mock.patch.object(hw.time, 'monotonic', return_value=1000):
            self.assertEqual(hw.usage_check(self.config, options)[0], 3)
        path = self.directory / '001122334455.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_text('broken json')
        with mock.patch.object(hw, 'measurement', return_value=sample()), mock.patch.object(hw.time, 'monotonic', return_value=1100):
            result = hw.usage_check(self.config, options)
        self.assertEqual(result[0], 3)
        self.assertIn('invalid state replaced', result[1])
        self.assertEqual(json.loads(path.read_text())['time'], 1100)

    def test_malformed_saved_time_resets_state(self):
        baseline, _ = hw.usage_sample(self.config, sample(), None, 1000, args())
        baseline['time'] = 'NaN'
        (self.directory / '001122334455.json').write_text(json.dumps(baseline))
        with mock.patch.object(hw, 'measurement', return_value=sample()):
            self.assertIn('invalid state replaced', hw.usage_check(self.config, args())[1])

    def test_corrupt_cached_interval_is_reset(self):
        baseline, _ = hw.usage_sample(self.config, sample(), None, 1000, args())
        state, _ = hw.usage_sample(self.config, sample('100.6'), baseline, 1900, args())
        path = self.directory / '001122334455.json'
        for damaged in [dict(state['result'], elapsed='0'), dict(state['result'], totals=[]),
                        dict(state['result'], deltas={'import': '-1'})]:
            path.write_text(json.dumps({**state, 'result': damaged}))
            with mock.patch.object(hw, 'measurement', return_value=sample('100.7')), mock.patch.object(hw.time, 'monotonic', return_value=1960):
                self.assertIn('invalid state replaced', hw.usage_check(self.config, args())[1])

    def test_request_failure_and_staleness_preserve_state(self):
        path = self.directory / '001122334455.json'
        path.write_text('original baseline')
        with mock.patch.object(hw, 'measurement', side_effect=hw.CheckError('failed', 2)):
            with self.assertRaises(hw.CheckError):
                hw.usage_check(self.config, args())
        self.assertEqual(path.read_text(), 'original baseline')
        with mock.patch.object(hw, 'measurement', return_value=sample()), mock.patch.object(hw, 'freshness', return_value=500):
            with self.assertRaises(hw.CheckError):
                hw.usage_check(self.config, args())
        self.assertEqual(path.read_text(), 'original baseline')

    def test_nonblocking_lock(self):
        with (self.directory / '001122334455.json.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaisesRegex(hw.CheckError, 'another usage check'):
                hw.usage_check(self.config, args())

    def test_config_permissions_and_required_serial(self):
        path = self.directory / 'device.json'
        config = p1(ca_file='/fixture/ca.pem')
        path.write_text(json.dumps(config))
        path.chmod(0o644)
        with self.assertRaisesRegex(hw.CheckError, 'world-accessible'):
            hw.read_config(path)
        path.chmod(0o640)
        self.assertEqual(hw.read_config(path)['serial'], '001122334455')
        config['serial'] = 'not-a-serial'
        path.write_text(json.dumps(config))
        with self.assertRaises(hw.CheckError):
            hw.read_config(path)

    def test_pair_saves_token_without_printing_it_or_changing_mode(self):
        path = self.directory / 'device.json'
        path.write_text('{}')
        path.chmod(0o640)
        output = io.StringIO()
        with mock.patch.object(hw, 'request', side_effect=[{'token': 'B' * 32}, {'serial': '001122334455'}]), contextlib.redirect_stdout(output):
            hw.pair(self.config, SimpleNamespace(config=str(path), user='local/nagios', timeout=2))
        self.assertNotIn('B' * 32, output.getvalue())
        self.assertEqual(json.loads(path.read_text())['token'], 'B' * 32)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_validate_config_does_not_contact_device(self):
        config = p1(kind='water', api=1, state_dir=str(self.directory))
        with mock.patch.object(hw, 'request') as request:
            self.assertEqual(hw.validate_config(config, args())[0], 0)
        request.assert_not_called()

    def test_health_rejects_wrong_device_and_reports_missing_timestamp(self):
        info = {'product_type': 'HWE-P1', 'serial': '001122334455', 'api_version': '2.3.0'}
        with mock.patch.object(hw, 'request', return_value=info), mock.patch.object(hw, 'measurement', return_value=sample()):
            self.assertIn('freshness unavailable', hw.health_check(p1(), args())[1])
        with mock.patch.object(hw, 'request', return_value={**info, 'serial': 'ffffffffffff'}):
            with self.assertRaises(hw.CheckError):
                hw.health_check(p1(), args())

    def test_cli_failures_have_nagios_exit_codes_and_no_tokens(self):
        path = self.directory / 'device.json'
        path.write_text(json.dumps(p1(ca_file='fixture.pem')))
        path.chmod(0o640)
        for exception, expected in [(hw.CheckError('API authentication rejected', 2), 2),
                                    (ssl.SSLError('fixture'), 2), (TimeoutError(), 2),
                                    (ValueError('invalid JSON'), 3)]:
            output = io.StringIO()
            with mock.patch.object(sys, 'argv', ['check_homewizard', '--config', str(path)]), mock.patch.object(hw, 'health_check', side_effect=exception), contextlib.redirect_stdout(output):
                self.assertEqual(hw.main(), expected)
            self.assertTrue(output.getvalue().startswith(hw.NAMES[expected] + ' - '))
            self.assertNotIn('A' * 32, output.getvalue())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observed.append((self.path, dict(self.headers)))
        self.send_response(self.server.response_status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(self.server.response_body)

    def log_message(self, *unused):
        pass


@contextlib.contextmanager
def local_server(context=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.observed = []
    server.response_status = 200
    server.response_body = b'{"power_w": 123.456}'
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class Transport(unittest.TestCase):
    def test_modern_strict_default_is_relaxed_only_for_device_context(self):
        context = ssl.create_default_context()
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        original_flags = context.verify_flags
        with mock.patch.object(hw.ssl, 'create_default_context', return_value=context):
            result = hw.device_tls_context('fixture-ca.pem')
        self.assertEqual(result.verify_flags, original_flags & ~ssl.VERIFY_X509_STRICT)
        self.assertEqual(result.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(result.check_hostname)
        self.assertTrue(result.hostname_checks_common_name)

    def test_real_v1_http_decimal_and_error_statuses(self):
        original = http.client.HTTPConnection
        with local_server() as server:
            def connection(address, timeout):
                return original(address, port=server.server_port, timeout=timeout)
            with mock.patch.object(hw.http.client, 'HTTPConnection', side_effect=connection):
                self.assertEqual(hw.request(p1(api=1), '/api/v1/data', 2)['power_w'], Decimal('123.456'))
                self.assertNotIn('Authorization', server.observed[-1][1])
                server.response_status = 401
                with self.assertRaises(hw.CheckError) as caught:
                    hw.request(p1(api=1), '/api/v1/data', 2)
                self.assertEqual(caught.exception.code, 2)
                server.response_status = 500
                with self.assertRaisesRegex(hw.CheckError, 'HTTP 500'):
                    hw.request(p1(api=1), '/api/v1/data', 2)

    def test_invalid_oversized_and_nonobject_json(self):
        original = http.client.HTTPConnection
        with local_server() as server:
            def connection(address, timeout):
                return original(address, port=server.server_port, timeout=timeout)
            with mock.patch.object(hw.http.client, 'HTTPConnection', side_effect=connection):
                for body in [b'[]', b'bad JSON', b'x' * 131073]:
                    server.response_body = body
                    with self.assertRaises((hw.CheckError, ValueError)):
                        hw.request(p1(api=1), '/api/v1/data', 2)

    @unittest.skipUnless(shutil.which('openssl'), 'openssl needed only for ephemeral TLS test certificates')
    def test_real_tls_common_name_validation_and_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert, key = root / 'ca.pem', root / 'key.pem'
            conf = root / 'openssl.cnf'
            conf.write_text('''[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = appliance/p1dongle/001122334455
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
''')
            result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                     '-days', '1', '-config', str(conf), '-keyout', str(key), '-out', str(cert)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Sign a device leaf with no Authority Key Identifier, like the
            # deployed meter. This exercises compatibility with a real chain.
            leaf, leaf_key, csr = root / 'device.pem', root / 'device.key', root / 'device.csr'
            extensions = root / 'device.ext'
            extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n')
            for command in [
                ['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', str(conf), '-keyout', str(leaf_key), '-out', str(csr)],
                ['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(cert), '-CAkey', str(key), '-CAcreateserial', '-days', '1', '-extfile', str(extensions), '-out', str(leaf)],
            ]:
                signed = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(signed.returncode, 0, signed.stderr)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(leaf, leaf_key)
            original = hw.DeviceHTTPS
            with local_server(server_context) as server:
                def connection(address, serial, context, timeout):
                    connection = original(address, serial, context, timeout)
                    connection.port = server.server_port
                    return connection
                with mock.patch.object(hw, 'DeviceHTTPS', side_effect=connection):
                    config = p1(ca_file=str(cert))
                    data = hw.request(config, '/api/measurement', 2)
                    self.assertEqual(data['power_w'], Decimal('123.456'))
                    headers = server.observed[-1][1]
                    self.assertEqual(headers['Authorization'], 'Bearer ' + 'A' * 32)
                    self.assertEqual(headers['X-Api-Version'], '2')
                    count = len(server.observed)
                    with self.assertRaises(ssl.SSLError):
                        hw.request({**config, 'serial': 'ffffffffffff'}, '/api/measurement', 2)
                    self.assertEqual(len(server.observed), count)  # no token sent to mismatched identity
                    with mock.patch.object(hw.ssl, 'create_default_context', return_value=ssl.create_default_context()):
                        with self.assertRaises(ssl.SSLError):
                            hw.request(config, '/api/measurement', 2)
                    self.assertEqual(len(server.observed), count)
                    server.response_status = 403
                    self.assertIsNone(hw.request(config, '/api/user', 2, pairing=True))
                    self.assertNotIn('Authorization', server.observed[-1][1])




if __name__ == '__main__':
    unittest.main()
