# check-homewizard

Nagios checks for HomeWizard P1 meters (API v1/v2) and watermeters (API v1).
Python 3.9+, Unix/Linux, standard library only; requires system timezone data.

Supports health, individual metrics, combined voltage/current/power phases and
windowed energy/water usage. Emits Nagios performance data. API v2 verifies TLS
and device identity; it never falls back to unencrypted API v1 after an error.

## Configuration and use

Keep device JSON files and paired tokens outside Git, owned by root and readable
only by the monitoring group (0640). State directories must be writable by the
monitoring account. See `examples/` for secret-free configuration templates;
replace the example IP, serial and CA path before use. API v2 requires the
HomeWizard CA and the device's twelve-character serial number.

```sh
python3 check_homewizard.py --help
python3 check_homewizard.py --config /etc/nagios4/private/homewizard/p1.json --validate-config
python3 check_homewizard.py --config /etc/nagios4/private/homewizard/p1.json --check health
python3 check_homewizard.py --config /etc/nagios4/private/homewizard/p1.json --check phases --phase-type voltage --warning 218.5:241.5 --critical 207:253
```

`--validate-config` performs local checks without contacting the device. Use
`--pair` only during deliberate setup after enabling pairing on the device;
it stores the token in the protected configuration. Never put tokens in CLI
arguments. Watermeter API v1 is unencrypted; use it only on a trusted network.

Usage checks need successive samples. Align `--window-seconds`, `--min-interval`
and `--max-gap` with the Nagios schedule. Configure thresholds for your own
installation. Monitoring state is not part of this repository.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Transport tests start loopback HTTP/TLS servers. The test suite does not
require access to production devices. Install the plugin in your Nagios
plugin directory and configure service commands for your installation.

## License

Licensed under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE](LICENSE).
