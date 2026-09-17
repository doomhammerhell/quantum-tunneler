"""Run bounded fuzz smoke checks, with a wall-clock watchdog including startup.

Example: python3 scripts/fuzz_smoke.py --toolchain nightly --seconds 20
Compiler/linker overrides may be passed through the environment. This script
never changes the global Rust toolchain or compiler configuration.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--toolchain', default='nightly')
parser.add_argument('--target')
parser.add_argument('--seconds', type=int, default=20)
parser.add_argument('--watchdog', type=int, default=180)
parser.add_argument('--sanitizer', choices=['address', 'none'], default='address')
parser.add_argument('targets', nargs='*', default=['ike_header', 'ike_payload', 'esp_packet', 'sa_proposal', 'ip_packet'])
args = parser.parse_args()
if not 1 <= args.seconds <= 3600 or args.watchdog <= args.seconds:
    parser.error('seconds must be 1..3600 and watchdog must exceed seconds')
root = Path(__file__).resolve().parent.parent
logs = root / 'target' / 'fuzz-smoke'
logs.mkdir(parents=True, exist_ok=True)
known = {'ike_header', 'ike_payload', 'esp_packet', 'sa_proposal', 'ip_packet'}
results = []
for name in args.targets:
    if name not in known:
        parser.error(f'unknown target: {name}')
    shutil.copytree(root / 'fuzz' / 'seeds' / name, root / 'fuzz' / 'corpus' / name, dirs_exist_ok=True)
    command = ['cargo', '+' + args.toolchain, 'fuzz', 'run', '--sanitizer', args.sanitizer]
    if args.target:
        command += ['--target', args.target]
    command += [name, '--', f'-max_total_time={args.seconds}', '-max_len=65536']
    path = logs / (name + '.log')
    with path.open('w') as output:
        process = subprocess.Popen(command, cwd=root, stdout=output, stderr=output,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=args.watchdog)
            status = 'passed' if code == 0 else 'failed'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            status = 'watchdog-timeout'
    result = {'target': name, 'status': status, 'log': str(path)}
    results.append(result)
    print(json.dumps(result), flush=True)
(logs / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
raise SystemExit(0 if all(r['status'] == 'passed' for r in results) else 1)
