#!/usr/bin/env python3
"""HomeWizard Nagios checks. Python 3.9+, standard library only."""

import argparse
import datetime as dt
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

NAMES = ('OK', 'WARNING', 'CRITICAL', 'UNKNOWN')
UNITS = {'power_w': 'W', 'power_l1_w': 'W', 'power_l2_w': 'W',
         'power_l3_w': 'W', 'voltage_l1_v': 'V', 'voltage_l2_v': 'V',
         'voltage_l3_v': 'V', 'current_l1_a': 'A', 'current_l2_a': 'A',
         'current_l3_a': 'A', 'energy_import_kwh': 'kWh',
         'energy_export_kwh': 'kWh', 'wifi_rssi_db': 'dBm',
         'wifi_strength': '%', 'uptime_s': 's', 'flow_lpm': 'L/min',
         'water_total_l': 'L', 'frequency_hz': 'Hz'}
SYSTEM_METRICS = {'wifi_rssi_db', 'uptime_s'}


class CheckError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise CheckError('invalid numeric measurement')
    try:
        result = Decimal(str(value))
    except InvalidOperation:
        raise CheckError('invalid numeric measurement') from None
    if not result.is_finite():
        raise CheckError('non-finite measurement')
    return result


def fmt(value):
    return format(number(value).quantize(Decimal('0.000001')), 'f').rstrip('0').rstrip('.') or '0'


def outside(value, specification):
    """Nagios range syntax; endpoints are inclusive; @ reverses the range."""
    if specification is None:
        return False
    inside_alert = specification.startswith('@')
    specification = specification.lstrip('@')
    if ':' in specification:
        low, high = specification.split(':', 1)
        low = Decimal('-Infinity') if low == '~' else number(low or '0')
        high = Decimal('Infinity') if not high else number(high)
    else:
        low, high = Decimal(0), number(specification)
    if low > high:
        raise CheckError('threshold lower bound exceeds upper bound')
    within = low <= number(value) <= high
    return within if inside_alert else not within


def status(value, warning, critical):
    return 2 if outside(value, critical) else 1 if outside(value, warning) else 0


def perf(label, value, unit='', warning=None, critical=None, minimum=''):
    # Nagios has no portable W/V/A/kWh/L UOM. Keep those units in labels.
    return f"'{label}'={fmt(value)}{unit};{warning or ''};{critical or ''};{minimum};"


def read_config(path, pairing=False):
    with open(path, encoding='utf-8') as stream:
        mode = stat.S_IMODE(os.fstat(stream.fileno()).st_mode)
        config = json.load(stream)
    if not isinstance(config, dict):
        raise CheckError('device configuration must be a JSON object')
    if not isinstance(config.get('address'), str):
        raise CheckError('configure a numeric device IP address')
    ipaddress.ip_address(config['address'])  # fixed IPs, no discovery or redirects
    if type(config.get('api')) is not int or config['api'] not in (1, 2):
        raise CheckError('configure api as 1 or 2')
    if config['api'] == 2:
        if mode & 0o007 or mode & 0o020:
            raise CheckError('v2 configuration must not be world-accessible or group-writable')
        serial = config.get('serial', '')
        if not re.fullmatch(r'[a-fA-F0-9]{12}', serial):
            raise CheckError('configure the P1 device serial (12 hexadecimal characters)')
        config['serial'] = serial.lower()
        if not pairing and not re.fullmatch(r'[A-F0-9]{32}', config.get('token', '')):
            raise CheckError('configure a valid v2 token; use --pair for initial setup')
        if not config.get('ca_file'):
            raise CheckError('configure the HomeWizard CA certificate file')
    if config.get('kind') not in ('p1', 'water'):
        raise CheckError('configure kind as p1 or water')
    if config['kind'] == 'water' and config['api'] != 1:
        raise CheckError('Watermeter currently requires API v1')
    config.setdefault('timezone', 'Europe/Amsterdam')
    config.setdefault('state_dir', '/run/nagios/homewizard')
    ZoneInfo(config['timezone'])
    return config


class DeviceHTTPS(http.client.HTTPSConnection):
    """Connect to an IP while verifying HomeWizard's certificate identity."""
    def __init__(self, address, serial, context, timeout):
        super().__init__(address, timeout=timeout, context=context)
        self.device_hostname = 'appliance/p1dongle/' + serial

    def connect(self):
        raw = socket.create_connection((self.host, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.device_hostname)
        except Exception:
            raw.close()
            raise


def device_tls_context(cafile):
    context = ssl.create_default_context(cafile=cafile)
    # HomeWizard device certificates can lack Authority Key Identifier.
    # Python 3.13+ enables strict RFC 5280 checks by default. Use OpenSSL's
    # compatible X.509 validation for this device CA, retaining required chain,
    # signature, validity and device-hostname verification.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # On LibreSSL-backed Python this is already true and read-only.
    if not context.hostname_checks_common_name:
        context.hostname_checks_common_name = True
    return context


def request(config, path, timeout, method='GET', body=None, pairing=False, cache=True):
    if (not cache or pairing or method != 'GET' or body is not None
            or path not in ('/api', '/api/system', '/api/measurement', '/api/v1/data')
            or not config.get('state_dir')):
        return network_request(config, path, timeout, method, body, pairing)
    directory = Path(config['state_dir'])
    if not directory.is_dir():
        raise CheckError('state directory missing; install the tmpfiles configuration')
    device = config.get('serial', config['address'].replace(':', '_'))
    cache_path = directory / (device + '.request-cache.json')
    # One mutex per device serializes all endpoints, including cache misses.
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    with os.fdopen(os.open(str(cache_path) + '.lock', flags, 0o600), 'r+') as lock:
        deadline = time.monotonic() + min(timeout, 5)
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise CheckError('device request queue busy; retry next check') from None
                time.sleep(0.05)
        identity = hashlib.sha256(json.dumps(
            {key: config.get(key) for key in ('address', 'serial', 'api', 'token', 'ca_file')},
            sort_keys=True).encode()).hexdigest()
        saved = {}
        try:
            with open(cache_path, encoding='utf-8') as stream:
                saved = json.loads(stream.read(600001))
            if not isinstance(saved, dict) or saved.get('identity') != identity:
                saved = {}
        except (FileNotFoundError, ValueError, TypeError):
            pass
        entry = saved.get(path)
        if isinstance(entry, dict) and isinstance(entry.get('data'), dict):
            try:
                age = time.monotonic() - float(entry['time'])
                if 0 <= age <= 10:
                    return entry['data']
            except (KeyError, ValueError, TypeError):
                pass
        # Never fall back to expired data when a new request fails.
        data = network_request(config, path, timeout)
        saved['identity'] = identity
        # Cache serialization preserves decimal precision; numeric strings are
        # accepted by number(), just like the original API numeric values.
        saved[path] = {'time': time.monotonic(), 'data': json.loads(json.dumps(data, default=str))}
        atomic_state(cache_path, saved)
        return data


def network_request(config, path, timeout, method='GET', body=None, pairing=False):
    headers = {'Accept': 'application/json'}
    if config['api'] == 2:
        context = device_tls_context(config['ca_file'])
        connection = DeviceHTTPS(config['address'], config['serial'], context, timeout)
        headers['X-Api-Version'] = '2'
        if not pairing:
            headers['Authorization'] = 'Bearer ' + config['token']
    else:
        connection = http.client.HTTPConnection(config['address'], timeout=timeout)
    if body is not None:
        headers['Content-Type'] = 'application/json'
        body = json.dumps(body)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if pairing and response.status == 403:
            return None
        if response.status in (401, 403):
            raise CheckError('API authentication rejected', 2)
        if response.status != 200:
            raise CheckError(f'API returned HTTP {response.status}', 2)
        payload = response.read(131073)
        if len(payload) > 131072:
            raise CheckError('API response exceeds size limit')
        data = json.loads(payload, parse_float=Decimal)
        if not isinstance(data, dict):
            raise CheckError('API response is not a JSON object')
        return data
    finally:
        connection.close()


def value(data, key):
    if key not in data or data[key] is None:
        raise CheckError(f'measurement {key} unavailable')
    return number(data[key])


def measurement(config, timeout):
    return request(config, '/api/measurement' if config['api'] == 2 else '/api/v1/data', timeout)


def freshness(data, timezone, now=None):
    if 'timestamp' not in data:
        return None
    stamp = dt.datetime.fromisoformat(data['timestamp'])
    now = now or dt.datetime.now(dt.timezone.utc)
    if stamp.tzinfo is None:
        zone = ZoneInfo(timezone)
        # A DSMR timestamp omits the UTC offset. Choose the nearest DST fold.
        options = [stamp.replace(tzinfo=zone, fold=fold) for fold in (0, 1)]
        stamp = min(options, key=lambda date: abs((now - date).total_seconds()))
    age = (now - stamp).total_seconds()
    if age < -120:
        raise CheckError('meter timestamp is in the future; check clocks/timezone')
    return max(0, age)


def ensure_fresh(data, config, limit):
    age = freshness(data, config['timezone']) if config['api'] == 2 else None
    if age is not None and age > limit:
        raise CheckError(f'measurement stale ({age:.0f}s old)', 2)
    return age


def metric_value(config, data, metric):
    if config['kind'] == 'water':
        if metric == 'flow_lpm':
            return value(data, 'active_liter_lpm')
        if metric == 'water_total_l':
            return value(data, 'total_liter_m3') * 1000
        if metric == 'wifi_strength':
            return value(data, metric)
        raise CheckError('metric unsupported for Watermeter')
    if config['api'] == 2:
        if metric == 'wifi_strength':
            raise CheckError('P1 v2 Wi-Fi uses wifi_rssi_db, not percent')
        return value(data, metric)
    mapping = {'energy_import_kwh': 'total_power_import_kwh',
               'energy_export_kwh': 'total_power_export_kwh'}
    key = mapping.get(metric, 'active_' + metric if metric.startswith(('power_', 'voltage_', 'current_', 'frequency_')) else metric)
    return value(data, key)


def metric_check(config, args):
    if args.metric in SYSTEM_METRICS and config['api'] == 2:
        data = request(config, '/api/system', args.timeout)
    else:
        data = measurement(config, args.timeout)
        ensure_fresh(data, config, args.max_age)
    measured = metric_value(config, data, args.metric)
    code = status(measured, args.warning, args.critical)
    unit = UNITS[args.metric]
    uom = '%' if unit == '%' else 's' if unit == 's' else ''
    label = args.metric
    return code, f'{label}={fmt(measured)} {unit}', perf(label, measured, uom, args.warning, args.critical)


def phases_check(config, args):
    if config['kind'] != 'p1':
        raise CheckError('phase checks require a P1 meter')
    if not args.phase_type:
        raise CheckError('--phase-type is required for phase checks')
    data = measurement(config, args.timeout)
    ensure_fresh(data, config, args.max_age)
    symbol = {'voltage': 'v', 'current': 'a', 'power': 'w'}[args.phase_type]
    results, metrics, states = [], [], []
    for phase in (1, 2, 3):
        metric = f'{args.phase_type}_l{phase}_{symbol}'
        measured = metric_value(config, data, metric)
        code = status(measured, args.warning, args.critical)
        states.append(code)
        results.append(f'L{phase}={fmt(measured)} {UNITS[metric]}' +
                       (f' ({NAMES[code]})' if code else ''))
        metrics.append(perf(metric, measured, '', args.warning, args.critical))
    return max(states), ', '.join(results), ' '.join(metrics)


def health_check(config, args):
    info = request(config, '/api', args.timeout)
    expected = 'HWE-P1' if config['kind'] == 'p1' else 'HWE-WTR'
    if info.get('product_type') != expected:
        raise CheckError('unexpected device product type', 2)
    if config['api'] == 2 and info.get('serial', '').lower() != config['serial']:
        raise CheckError('unexpected device serial', 2)
    if not str(info.get('api_version', '')).startswith('2' if config['api'] == 2 else 'v1'):
        raise CheckError('unexpected API version', 2)
    data = measurement(config, args.timeout)
    age = ensure_fresh(data, config, args.max_age)
    metric_value(config, data, 'power_w' if config['kind'] == 'p1' else 'flow_lpm')
    text = 'API responding; measurements valid'
    text += '; freshness unavailable' if age is None else f'; measurement age={age:.0f}s'
    return 0, text, '' if age is None else perf('measurement_age', age, 's', critical=str(args.max_age), minimum='0')


def counters(config, data):
    if config['kind'] == 'water':
        totals = {'water': metric_value(config, data, 'water_total_l')}
    else:
        totals = {'import': metric_value(config, data, 'energy_import_kwh')}
        export_key = 'energy_export_kwh' if config['api'] == 2 else 'total_power_export_kwh'
        if export_key in data:
            totals['export'] = value(data, export_key)
    if any(total < 0 for total in totals.values()):
        raise CheckError('negative cumulative meter counter')
    return totals


def atomic_state(path, state, metadata=None):
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(state, stream)
            stream.flush()
            if metadata is not None:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def usage_result(config, result, args, cached=False):
    water = config['kind'] == 'water'
    key, unit = ('water', 'L') if water else ('import', 'kWh')
    delta = number(result['deltas'][key])
    elapsed = number(result['elapsed'])
    if not args.min_interval <= elapsed <= args.max_gap:
        raise CheckError('invalid saved interval length')
    if any(number(v) < 0 for v in result['deltas'].values()):
        raise CheckError('invalid saved usage delta')
    if any(number(v) < 0 for v in result['totals'].values()):
        raise CheckError('invalid saved cumulative counter')
    window_seconds = number(args.window_seconds)
    equivalent = delta * window_seconds / elapsed
    rate = delta * (60 if water else 3600000) / elapsed
    measured = rate / 1000 if args.rate_thresholds and not water else rate if args.rate_thresholds else equivalent
    code = status(measured, args.warning, args.critical)
    if args.rate_thresholds:
        message = f'{fmt(delta)} {unit} over {fmt(elapsed / 60)} min; {fmt(measured)} {"L/min" if water else "kW"} average'
    else:
        message = f'{fmt(delta)} {unit} over {fmt(elapsed / 60)} min; {fmt(equivalent)} {unit}/{fmt(window_seconds / 60)}min'
    if cached:
        message += '; previous interval retained until next sample'
    metrics = [perf(f'{key}_{unit}_{int(window_seconds / 60)}m', equivalent,
                    warning=None if args.rate_thresholds else args.warning,
                    critical=None if args.rate_thresholds else args.critical, minimum='0'),
               perf(f'{key}_{unit}_interval', delta, minimum='0'), perf('interval', elapsed, 's', minimum='0')]
    metrics.append(perf('average_flow_lpm' if water else 'average_import_w', rate, minimum='0'))
    if args.rate_thresholds:
        metrics.append(perf('average_flow_Lpm' if water else 'average_import_kW',
                            measured, warning=args.warning, critical=args.critical, minimum='0'))
    if 'export' in result['deltas']:
        exported = number(result['deltas']['export'])
        metrics.extend([perf('export_kWh_interval', exported, minimum='0'),
                        perf('export_kWh_15m', exported * 900 / elapsed, minimum='0')])
    elif not water:
        message += '; export counter unavailable'
    for name, total in result['totals'].items():
        metrics.append(perf(f'{name}_{unit}_total', total, minimum='0'))
    return code, message, ' '.join(metrics)


def usage_sample(config, data, previous, now, args):
    totals = counters(config, data)
    identity = [config['address'], config.get('serial'), data.get('unique_id'), config['api'], config['kind']]
    baseline = {'version': 1, 'identity': identity, 'time': now,
                'totals': {key: str(total) for key, total in totals.items()}}
    reason = None
    if previous is None:
        reason = 'usage baseline established; next interval pending'
    elif previous.get('version') != 1 or previous.get('identity') != identity:
        reason = 'device identity changed; usage baseline reset'
    else:
        old = previous['totals']
        elapsed = now - float(previous['time'])
        if not math.isfinite(elapsed):
            raise CheckError('invalid saved sampling time')
        if set(old) != set(totals):
            reason = 'available counters changed; usage baseline reset'
        elif any(totals[key] < number(old[key]) for key in totals):
            reason = 'meter counter decreased; usage baseline reset'
        elif elapsed <= 0 or elapsed > args.max_gap:
            reason = 'sampling gap/clock reset; usage baseline reset'
        elif elapsed < args.min_interval:
            if 'result' in previous:
                return previous, usage_result(config, previous['result'], args, cached=True)
            return previous, (3, 'usage baseline established; next interval pending', '')
        else:
            result = {'elapsed': str(elapsed),
                      'deltas': {key: str(totals[key] - number(old[key])) for key in totals},
                      'totals': baseline['totals']}
            baseline['result'] = result
            return baseline, usage_result(config, result, args)
    return baseline, (3, reason, '')


def usage_check(config, args):
    directory = Path(config['state_dir'])
    # Directory is provisioned by tmpfiles, never created as an accidental root-owned directory.
    if not directory.is_dir():
        raise CheckError('state directory missing; install the tmpfiles configuration')
    name = config.get('serial', config['address'].replace(':', '_'))
    path = directory / (name + '.json')
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    with os.fdopen(os.open(str(path) + '.lock', flags, 0o600), 'r+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CheckError('another usage check is running') from None
        data = measurement(config, args.timeout)
        ensure_fresh(data, config, args.max_age)
        previous = None
        corrupt = False
        try:
            with open(path, encoding='utf-8') as stream:
                previous = json.load(stream)
            if not isinstance(previous, dict):
                raise ValueError()
        except FileNotFoundError:
            pass
        except (ValueError, TypeError):
            corrupt = True
        try:
            state, result = usage_sample(config, data, previous, time.monotonic(), args)
        except (KeyError, ValueError, TypeError, AttributeError, ArithmeticError, CheckError):
            # Validate device counters first; only malformed state gets reset.
            counters(config, data)
            state, result = usage_sample(config, data, None, time.monotonic(), args)
            corrupt = True
        if state != previous:
            atomic_state(path, state)
        if corrupt:
            return 3, 'invalid state replaced; usage baseline reset', ''
        return result


def pair(config, args):
    if config['api'] != 2:
        raise CheckError('pairing requires API v2')
    if not re.fullmatch(r'local/[a-zA-Z0-9\-_/\\# ]{1,40}', args.user):
        raise CheckError('invalid local pairing user name')
    print('Press the P1 button when it flashes. Waiting up to 90 seconds.', flush=True)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        response = request(config, '/api/user', args.timeout, 'POST', {'name': args.user}, pairing=True)
        if response is not None:
            token = response.get('token', '')
            if not re.fullmatch(r'[A-F0-9]{32}', token):
                raise CheckError('pairing returned an invalid token')
            config['token'] = token
            # Verify before saving; never print the token.
            info = request(config, '/api', args.timeout, cache=False)
            if info.get('serial', '').lower() != config['serial']:
                raise CheckError('pairing device serial mismatch')
            path = Path(args.config)
            atomic_state(path, config, metadata=path.stat())
            print('Pairing complete; token saved without changing configuration permissions.')
            return
        time.sleep(2)
    raise CheckError('pairing timed out; press the device button and retry')


def validate_config(config, args):
    """Deployment preflight: validate local prerequisites without contacting devices."""
    if config['api'] == 2:
        device_tls_context(config['ca_file'])
    directory = Path(config['state_dir'])
    if not directory.is_dir() or not os.access(directory, os.W_OK | os.X_OK):
        raise CheckError('usage state directory missing or not writable by this user')
    return 0, 'device configuration and local prerequisites valid', ''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--check', choices=('health', 'metric', 'usage', 'phases'), default='health')
    parser.add_argument('--metric', choices=sorted(UNITS))
    parser.add_argument('--phase-type', choices=('voltage', 'current', 'power'))
    parser.add_argument('--warning')
    parser.add_argument('--critical')
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--max-age', type=float, default=180)
    parser.add_argument('--rate-thresholds', action='store_true')
    parser.add_argument('--window-seconds', type=float, default=900)
    parser.add_argument('--min-interval', type=float, default=750)
    parser.add_argument('--max-gap', type=float, default=1800)
    parser.add_argument('--pair', action='store_true')
    parser.add_argument('--validate-config', action='store_true', help='validate local prerequisites only; no device requests')
    parser.add_argument('--user', default='local/nagios')
    args = parser.parse_args()
    try:
        for option in (args.timeout, args.max_age, args.min_interval, args.max_gap, args.window_seconds):
            if not math.isfinite(option) or option <= 0:
                raise CheckError('time limits must be finite and positive')
        if args.window_seconds % 60 != 0:
            raise CheckError('window-seconds must be a whole number of minutes')
        if args.max_gap <= args.min_interval:
            raise CheckError('max-gap must exceed min-interval')
        outside(0, args.warning)
        outside(0, args.critical)
        config = read_config(args.config, pairing=args.pair)
        if args.pair and args.validate_config:
            raise CheckError('--pair and --validate-config are mutually exclusive')
        if args.pair:
            pair(config, args)
            return 0
        if args.check == 'metric' and not args.metric:
            raise CheckError('--metric is required for metric checks')
        checks = {'metric': metric_check, 'health': health_check, 'usage': usage_check, 'phases': phases_check}
        code, message, metrics = (validate_config if args.validate_config else checks[args.check])(config, args)
    except CheckError as error:
        code, message, metrics = error.code, str(error), ''
    except ssl.SSLCertVerificationError as error:
        reason = ' '.join(error.verify_message.split())
        code, message, metrics = 2, f'TLS certificate validation failed ({error.verify_code}): {reason}', ''
    except ssl.SSLError:
        code, message, metrics = 2, 'TLS certificate/identity validation failed', ''
    except (socket.timeout, TimeoutError, ConnectionError, http.client.HTTPException):
        code, message, metrics = 2, 'device connection failed or timed out', ''
    except OSError as error:
        code = 2 if error.errno in (101, 111, 113) else 3
        message, metrics = 'network or configuration/state file access failed', ''
    except (ValueError, TypeError, KeyError, InvalidOperation):
        code, message, metrics = 3, 'invalid configuration, timestamp or JSON data', ''
    print(f'{NAMES[code]} - {message}' + (f' | {metrics}' if metrics else ''))
    return code


if __name__ == '__main__':
    sys.exit(main())
