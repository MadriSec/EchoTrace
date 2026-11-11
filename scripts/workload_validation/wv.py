#!/usr/bin/env python3
"""Helpers for workload_validation.sh.

  wv.py trace --bpftrace FILE --match STR --out PREFIX
      Turn the bpftrace capture into the set of syscalls made by the containers
      whose cgroup path contains STR (the containers under test).
      Writes PREFIX.observed.tsv (syscall, nr, count, first_process, containers)
      and PREFIX.observed.txt (names only).

  wv.py diff --observed PREFIX.observed.tsv --policy POLICY.json
             --sources-dir RESULTS_DIR [--runtime runc.txt] --out PREFIX
      Diff observed syscalls against the SysJava policy:
        missing = observed - policy   (workload needs it, SysJava did not find it)
        used    = observed & policy
        unused  = policy - observed   (allowed, not exercised by this workload)
      Policy names that are not x86_64 syscalls are excluded and reported.
      Each policy syscall is attributed to the SysJava source(s) that produced it.
      Writes PREFIX.{missing,used,unused}.txt, PREFIX.diff.tsv,
      PREFIX.by_source.tsv and PREFIX.summary (key=value, read by the driver).
"""
import argparse
import collections
import ctypes
import ctypes.util
import json
import pathlib
import re
import sys

X86_64 = 0xc000003e  # AUDIT_ARCH_X86_64 == SCMP_ARCH_X86_64

# Per-source syscall files written by the SysJava pipeline (merge_all_syscalls.py).
SOURCES = [
    ('libraries', 'library_syscalls.txt'),         # Java bindings -> native libraries
    ('binaries', 'binary_syscalls.txt'),           # executables observed via execve
    ('unmapped_libs', 'unanalysed_syscalls.txt'),  # loaded libs not reached by a binding
    ('jna_ffi', 'union_syscalls.txt'),             # JNA / FFI call sites
]


# --------------------------------------------------------------------- names
def make_resolver():
    fn = None
    for name in (ctypes.util.find_library('seccomp'), 'libseccomp.so.2'):
        if not name:
            continue
        try:
            fn = ctypes.CDLL(name).seccomp_syscall_resolve_num_arch
            fn.restype = ctypes.c_char_p
            fn.argtypes = [ctypes.c_uint32, ctypes.c_int]
            break
        except (OSError, AttributeError):
            fn = None
    table = {}
    for hdr in ('/usr/include/x86_64-linux-gnu/asm/unistd_64.h', '/usr/include/asm/unistd_64.h'):
        try:
            text = pathlib.Path(hdr).read_text()
            table = {int(n): s for s, n in re.findall(r'#define __NR_(\w+)\s+(\d+)', text)}
            break
        except OSError:
            pass
    if fn is None and not table:
        sys.exit('error: cannot map syscall numbers to names: install libseccomp2 or linux-libc-dev')

    def resolve(nr):
        if fn is not None:
            r = fn(X86_64, nr)
            if r:
                return r.decode()
        return table.get(nr, f'nr_{nr}')
    return resolve


def make_validator():
    """name -> True if it is a real x86_64 syscall name (as libseccomp/Docker see it)."""
    fn = None
    for name in (ctypes.util.find_library('seccomp'), 'libseccomp.so.2'):
        if not name:
            continue
        try:
            fn = ctypes.CDLL(name).seccomp_syscall_resolve_name_arch
            fn.restype = ctypes.c_int
            fn.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
            break
        except (OSError, AttributeError):
            fn = None
    if fn is not None:
        return lambda n: fn(X86_64, n.encode()) >= 0
    resolve = make_resolver()
    known = {resolve(nr) for nr in range(512)}
    return lambda n: n in known


def read_names(path):
    p = pathlib.Path(path)
    return {l.strip() for l in p.read_text().splitlines() if l.strip()} if p.is_file() else set()


# --------------------------------------------------------------------- trace
def cmd_trace(a):
    cg_path, counts, first, lost = {}, collections.Counter(), {}, []
    per_cg = collections.defaultdict(set)
    for line in open(a.bpftrace, errors='replace'):
        line = line.rstrip('\n')
        if line.startswith('CG '):
            _, cg, path = line.split(' ', 2)
            cg_path[int(cg)] = path
        elif line.startswith('FIRST '):
            _, cg, nr, comm = (line.split(' ', 3) + [''])[:4]
            first[(int(cg), int(nr))] = comm
        elif m := re.match(r'@n\[(\d+), (\d+)\]: (\d+)', line):
            cg, nr, n = map(int, m.groups())
            counts[(cg, nr)] += n
        elif 'Lost' in line and 'event' in line:
            lost.append(line)

    targets = {cg: p for cg, p in cg_path.items() if a.match in p}
    if not targets:
        sys.exit(f'error: no traced cgroup path contains {a.match!r}; '
                 'was --cgroup-parent applied to the container under test?')

    resolve = make_resolver()
    agg = {}
    for (cg, nr), n in counts.items():
        if cg not in targets:
            continue
        name = resolve(nr)
        e = agg.setdefault(name, {'nr': nr, 'count': 0, 'first': '', 'cgs': set()})
        e['count'] += n
        e['first'] = e['first'] or first.get((cg, nr), '')
    for e in agg.values():
        e['first'] = e['first'] or '-'
        e['cgs'].add(re.sub(r'.*docker-([0-9a-f]{12}).*', r'\1', targets[cg]))

    names = sorted(agg)
    with open(a.out + '.observed.tsv', 'w') as fh:
        fh.write('syscall\tnr\tcount\tfirst_process\tcontainers\n')
        for s in names:
            e = agg[s]
            fh.write(f"{s}\t{e['nr']}\t{e['count']}\t{e['first']}\t{','.join(sorted(e['cgs']))}\n")
    pathlib.Path(a.out + '.observed.txt').write_text(''.join(s + '\n' for s in names))
    if lost:
        pathlib.Path(a.out + '.warnings.txt').write_text(
            'bpftrace lost events (cgroup/first-process labels may be incomplete; counts are not affected)\n'
            + '\n'.join(lost) + '\n')
    print(f'trace: {len(names)} distinct syscalls, {sum(e["count"] for e in agg.values())} calls, '
          f'{len(targets)} container(s)' + (' [WARNING: lost events]' if lost else ''))


# --------------------------------------------------------------------- diff
def cmd_diff(a):
    listed = {n for s in json.loads(pathlib.Path(a.policy).read_text()).get('syscalls', [])
              if s.get('action') == 'SCMP_ACT_ALLOW' for n in s.get('names', [])}
    # names that are not x86_64 syscalls (e.g. sysdig events such as "procexit") are
    # ignored by Docker; keep them out of the diff and report them
    is_syscall = make_validator()
    invalid = sorted(n for n in listed if not is_syscall(n))
    policy = listed - set(invalid)

    observed = {}
    with open(a.observed) as fh:
        next(fh)
        for line in fh:
            s, nr, count, first, _ = line.rstrip('\n').split('\t')
            observed[s] = (int(count), first)

    # syscall -> set of SysJava sources that contributed it
    src_of = collections.defaultdict(set)
    root = pathlib.Path(a.sources_dir)
    found = []
    for label, fname in SOURCES:
        files = sorted(root.rglob(fname)) if root.is_dir() else []
        found += [f'{label}: {f}' for f in files]
        for f in files:
            for s in read_names(f):
                src_of[s].add(label)
    if a.runtime:
        for s in read_names(a.runtime):
            src_of[s].add('runtime')
    for s in policy:
        if not src_of[s]:
            src_of[s].add('unattributed')

    missing = sorted(set(observed) - policy)
    used = sorted(set(observed) & policy)
    unused = sorted(policy - set(observed))

    for kind, lst in (('missing', missing), ('used', used), ('unused', unused)):
        pathlib.Path(f'{a.out}.{kind}.txt').write_text(''.join(s + '\n' for s in lst))

    with open(a.out + '.diff.tsv', 'w') as fh:
        fh.write('syscall\tstatus\tcount\tfirst_process\tsysjava_sources\n')
        for kind, lst in (('missing', missing), ('used', used), ('unused', unused)):
            for s in lst:
                count, first = observed.get(s, (0, ''))
                srcs = ','.join(sorted(src_of[s])) if s in policy else '-'
                fh.write(f'{s}\t{kind}\t{count}\t{first}\t{srcs}\n')

    labels = [l for l, _ in SOURCES] + ['runtime', 'unattributed']
    with open(a.out + '.by_source.tsv', 'w') as fh:
        fh.write('source\tin_policy\tused\tunused\tunused_only_from_this_source\n')
        for l in labels:
            inpol = {s for s in policy if l in src_of[s]}
            if not inpol:
                continue
            fh.write(f'{l}\t{len(inpol)}\t{len(inpol & set(used))}\t{len(inpol & set(unused))}\t'
                     f'{len({s for s in inpol & set(unused) if src_of[s] == {l}})}\n')

    pct = 100.0 * len(used) / len(policy) if policy else 0.0
    summary = {
        'n_policy_listed': len(listed), 'invalid_policy_names': ','.join(invalid) or '-',
        'n_policy': len(policy), 'n_observed': len(observed), 'n_used': len(used),
        'n_missing': len(missing), 'n_unused': len(unused), 'pct_policy_used': f'{pct:.1f}',
        'missing': ','.join(missing) or '-',
    }
    pathlib.Path(a.out + '.summary').write_text(''.join(f'{k}={v}\n' for k, v in summary.items()))
    if invalid:
        print(f'note: policy lists {len(invalid)} names that are not x86_64 syscalls (ignored): {",".join(invalid)}')
    if not found:
        print(f'note: no per-source syscall files under {a.sources_dir}; sources reported as unattributed')
    print(f"diff: policy={len(policy)} observed={len(observed)} used={len(used)} "
          f"missing={len(missing)} unused={len(unused)} ({pct:.1f}% of policy exercised)"
          + (f"  MISSING: {summary['missing']}" if missing else ''))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    t = sub.add_parser('trace')
    t.add_argument('--bpftrace', required=True)
    t.add_argument('--match', required=True)
    t.add_argument('--out', required=True)
    d = sub.add_parser('diff')
    d.add_argument('--observed', required=True)
    d.add_argument('--policy', required=True)
    d.add_argument('--sources-dir', required=True)
    d.add_argument('--runtime')
    d.add_argument('--out', required=True)
    a = ap.parse_args()
    {'trace': cmd_trace, 'diff': cmd_diff}[a.cmd](a)


if __name__ == '__main__':
    main()
