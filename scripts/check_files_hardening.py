"""Check /files/ hardening that byte checks cannot see. Test stack only."""
import argparse
import re
import subprocess
import urllib.error
import urllib.request

from ctf_smoke import PROJECT

NGINX = f'{PROJECT}-nginx-1'
FILES_DIR = '/usr/share/nginx/files'


def request(base, path, method='GET'):
    req = urllib.request.Request(base.rstrip('/') + path, method=method,
                                 data=b'x' if method in ('POST', 'PUT') else None)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read(4096)
        return response.status, response.headers.get('Content-Type', '').lower()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args):
    return subprocess.run(['docker', *args], capture_output=True, text=True, timeout=20, check=False)


def verify(base, text_path, js_path):
    status, content_type = request(base, text_path)
    require(status == 200 and content_type.startswith('text/plain'), f'{text_path}: expected text/plain')
    status, content_type = request(base, js_path)
    require(status == 200 and 'javascript' in content_type, f'{js_path}: expected a JavaScript type')
    for method in ('POST', 'PUT', 'DELETE'):
        status, _ = request(base, text_path, method)
        require(status == 403, f'{method} {text_path}: expected 403, got {status}')
    write = docker('exec', NGINX, 'sh', '-c', f'touch {FILES_DIR}/.write-probe')
    require(write.returncode != 0, 'nginx can write to the materials directory')
    mounts = docker('inspect', '-f', f'{{{{range .Mounts}}}}{{{{if eq .Destination "{FILES_DIR}"}}}}'
                    '{{.RW}}{{end}}{{end}}', NGINX)
    require(mounts.returncode == 0 and mounts.stdout.strip() == 'false', 'materials mount is not read-only')
    config = docker('exec', NGINX, 'nginx', '-T')
    require(config.returncode == 0 and re.search(r'disable_symlinks\s+on;', config.stdout),
            'disable_symlinks is not enabled')
    print('PASS: /files/ read-only mount, no writes, GET only, text and JS types, symlinks disabled')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='http://127.0.0.1:18080')
    parser.add_argument('--text', default='/files/crypto-01/challenge.txt')
    parser.add_argument('--js', default='/files/web-02/probe.js')
    args = parser.parse_args()
    verify(args.base, args.text, args.js)


if __name__ == '__main__':
    main()
