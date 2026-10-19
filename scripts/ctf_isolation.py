"""Check only the dedicated cyberarena-ctf-check stack; never target working data."""

import json
import subprocess

from ctf_smoke import PROJECT

PREFIX = PROJECT


def main():
    addresses = {}
    for service in ('app', 'nginx'):
        result = subprocess.run(
            ['docker', 'inspect', f'{PREFIX}-{service}-1', '--format', '{{json .NetworkSettings.Networks}}'],
            check=True, capture_output=True, text=True,
        )
        networks = json.loads(result.stdout)
        addresses[service] = networks[f'{PREFIX}_app-net']['IPAddress']
    checks = r'''
import json, os, socket, tempfile, urllib.request, urllib.error
from pathlib import Path
results = {}
for name in ('app', 'nginx'):
    try:
        socket.getaddrinfo(name, 8000)
    except socket.gaierror:
        results[name + '_dns_blocked'] = True
    else:
        raise AssertionError('Lab resolves protected service ' + name)
targets = [(ADDRESSES['app'],8000), (ADDRESSES['nginx'],80), ('1.1.1.1',443), ('host.docker.internal',18080)]
for host, port in targets:
    try:
        with socket.create_connection((host,port), timeout=2):
            raise AssertionError('Lab reached protected endpoint')
    except OSError:
        pass
results['direct_ips_host_and_internet_blocked'] = True
try:
    urllib.request.urlopen('http://lab-gateway:8000/api/health', timeout=3)
except urllib.error.HTTPError as exc:
    assert exc.code == 404
else:
    raise AssertionError('Gateway proxies app API')
results['gateway_has_no_app_route'] = True
assert not Path('/code/data').exists() and not Path('/var/run/docker.sock').exists()
assert os.getuid() != 0
try:
    with tempfile.NamedTemporaryFile(dir='/lab'):
        raise AssertionError('Lab filesystem is writable')
except OSError:
    pass
caps = next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
assert int(caps.split()[1], 16) == 0
results['filesystem_user_capabilities_and_db_isolated'] = True
print(json.dumps(results))
'''
    code = 'ADDRESSES = ' + repr(addresses) + '\n' + checks
    subprocess.run(['docker', 'exec', '-i', f'{PREFIX}-lab-web-1', 'python', '-'],
                   input=code, text=True, check=True)


if __name__ == '__main__':
    main()
