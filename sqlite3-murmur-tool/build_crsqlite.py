#!/usr/bin/env python3
"""Build the pinned upstream cr-sqlite core and isolate Rust-internal symbols."""
import argparse
import json
import os
import shlex
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--target-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--cc', default='x86_64-w64-mingw32-gcc')
    parser.add_argument('--nm', default='nm')
    parser.add_argument('--objcopy', default='objcopy')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'deps/crsqlite'
    pin = json.loads((source / 'UPSTREAM.json').read_text())
    env = os.environ.copy()
    env['CRSQLITE_COMMIT_SHA'] = pin['revision']
    if args.target.endswith('windows-gnu') and os.name != 'nt':
        # Bindgen needs the target SDK, rather than Linux's C headers.
        runtime = Path(subprocess.check_output(
            [args.cc, '-print-file-name=libmingw32.a'], text=True).strip()).resolve()
        include = runtime.parent.parent / 'include'
        if not include.is_dir():
            raise SystemExit('Cannot locate MinGW headers; set BINDGEN_EXTRA_CLANG_ARGS for your SDK')
        clang_args = shlex.join(['--target=x86_64-w64-windows-gnu', '-isystem', str(include)])
        env['BINDGEN_EXTRA_CLANG_ARGS'] = env.get('BINDGEN_EXTRA_CLANG_ARGS', '') + ' ' + clang_args
    subprocess.run([args.cargo, '+' + pin['rust_toolchain'], 'build', '--locked',
                    '--release', '--features', 'static,omit_load_extension',
                    '--target', args.target, '--target-dir', str(args.target_dir.resolve()),
                    '--manifest-path', str(source / 'rs/bundle_static/Cargo.toml')],
                   env=env, check=True)
    archive = args.target_dir.resolve() / args.target / 'release/libcrsql_bundle_static.a'
    symbols = subprocess.check_output([args.nm, '-g', '--defined-only', str(archive)], text=True)
    mapping = set()
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[-2] not in 'ABCDGIRSTVWu':
            continue
        symbol = fields[-1]
        if symbol.startswith(('crsql_', 'sqlite3_')):
            continue
        mapping.add(symbol)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    rename = args.output.with_suffix('.symbols')
    rename.write_text(''.join(f'{symbol} crsql_isolated_{symbol}\n' for symbol in sorted(mapping)))
    subprocess.run([args.objcopy, '--redefine-syms=' + str(rename), str(archive),
                    str(args.output)], check=True)


if __name__ == '__main__':
    main()
