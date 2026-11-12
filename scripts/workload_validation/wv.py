#!/usr/bin/env python3
"""Helpers for workload_validation.sh.

  wv.py trace --bpftrace FILE --match STR --out PREFIX
      Turn the bpftrace capture into the set of syscalls made by the containers
      whose cgroup path contains STR (the containers under test).
      Writes PREFIX.observed.tsv (syscall, nr, count, first_process, containers)
      and PREFIX.observed.txt (names only).

  wv.py diff --observed PREFIX.observed.tsv --policy POLICY.json
             --sources-dir RESULTS_DIR [--runtime runc.txt ...] --out PREFIX
      Diff observed syscalls against the SysJava policy:
        missing = observed - policy   (workload needs it, SysJava did not find it)
        used    = observed & policy
        unused  = policy - observed   (allowed, not exercised by this workload)
      Policy names that are not x86_64 syscalls are excluded and reported.
      Each policy syscall is attributed to the SysJava source(s) that produced it.
      Writes PREFIX.{missing,used,unused}.txt, PREFIX.diff.tsv,
      PREFIX.by_source.tsv and PREFIX.summary (key=value, read by the driver).

  wv.py artifacts --files PREFIX.sysdig.files --execve PREFIX.sysdig.execve
                  --match STR [--injected PREFIX.injected] --sources-dir RESULTS_DIR --out PREFIX
      Diff the binaries executed and the native libraries (and jars) opened by
      the containers under test against what SysJava's startup discovery saw
      (Dynamic_Analysis/sysdig_outputs_*/ under RESULTS_DIR):
        new = observed under the workload - startup discovery
      Writes PREFIX.observed_{binaries,libs,jars}.txt, PREFIX.new_{binaries,libs,jars}.txt,
      PREFIX.artifacts.tsv (one line per observed artefact, with notes) and
      PREFIX.artifacts.summary (key=value).
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
        e['cgs'].add(re.sub(r'.*docker-([0-9a-f]{12}).*', r'\1', targets[cg]))
    for e in agg.values():
        e['first'] = e['first'] or '-'

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
    for f in a.runtime or []:
        for s in read_names(f):
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


# ----------------------------------------------------------------- artifacts
SEP = '|~|'   # field separator of the sysdig captures (see workload_validation.sh)
LIB_RE = re.compile(r'\.so(\.[0-9]+)*$')
# Not libraries, although the capture filter ("contains .so") lets them through;
# /gconv/ and /audit/ are dropped by startup discovery as well (sysdig_unified.sh).
NOT_LIB_RE = re.compile(r'/(gconv|audit)/|^/etc/ld\.so')
TEMP_RE = re.compile(r'^/(tmp|var/tmp|dev/shm|run)/')


def base(path):
    return path.rstrip('/').rsplit('/', 1)[-1]


def lib_stem(path):
    """libnss_files-2.28.so, libnss_files.so.2 -> libnss_files"""
    return re.sub(r'-[0-9][0-9.]*$', '', re.sub(r'\.so(\.[0-9]+)*$', '', base(path)))


def is_lib(path):
    return bool(LIB_RE.search(path)) and not NOT_LIB_RE.search(path)


def read_paths(files):
    return {l.strip() for f in files for l in f.read_text(errors='replace').splitlines() if l.strip()}


def cmd_artifacts(a):
    cids = set()
    if a.injected and pathlib.Path(a.injected).is_file():
        cids = {l.split()[1] for l in pathlib.Path(a.injected).read_text().splitlines() if l.startswith('cid ')}

    def target(cid, cgroups):
        return a.match in cgroups or any(c.startswith(cid) for c in cids if cid and cid != 'host')

    # --- observed under the workload
    libs, jars, seen_cids, n_files = set(), set(), set(), 0
    for line in open(a.files, errors='replace'):
        f = line.rstrip('\n').split(SEP, 4)
        if len(f) != 5:
            continue
        _evt, _proc, cid, cgroups, path = f
        n_files += 1
        if not path.startswith('/') or not target(cid, cgroups):
            continue
        seen_cids.add(cid)
        if is_lib(path):
            libs.add(path)
        elif path.endswith('.jar'):
            jars.add(path)

    # execve: the exit event ('<') of a successful call describes the new program
    bins, entered, n_exec = {}, {}, 0
    for line in open(a.execve, errors='replace'):
        f = line.rstrip('\n').split(SEP, 6)
        if len(f) != 7:
            continue
        direction, proc, cid, cgroups, exepath, filename, _ = f
        n_exec += 1
        if not target(cid, cgroups):
            continue
        seen_cids.add(cid)
        if direction == '<' and exepath.startswith('/'):
            bins.setdefault(exepath, proc)
        elif direction == '>' and filename.startswith('/'):
            entered.setdefault(filename, proc)
    note = ''
    if not bins and entered:
        # this sysdig reports no usable exit events: fall back to the requested paths,
        # which may include failed PATH lookups
        bins, note = entered, 'binaries taken from execve enter events (may include failed lookups)'
    bins = {p: c for p, c in bins.items() if not re.match(r'^/(proc|sys|dev|memfd)', p)}

    if not seen_cids:
        sys.exit(f'error: no captured event belongs to a container under test '
                 f'({n_files} file events, {n_exec} execve events read; match={a.match!r}, {len(cids)} known cid(s))')

    # --- startup discovery (baseline)
    root = pathlib.Path(a.sources_dir)
    f_bins = sorted(root.rglob('binaries_resolved_*.txt'))
    f_libs = sorted(root.rglob('jni_libs_opened.txt'))
    f_jars = sorted(root.rglob('jars_unique_*.txt'))
    if not f_libs or not f_bins:
        sys.exit(f'error: startup discovery files (binaries_resolved_*.txt, jni_libs_opened.txt) not found under {root}')
    base_bins = read_paths(f_bins)
    # binaries SysJava analysed, by file name: includes the few added by hand after discovery
    analysed_bins = {f.name for d in root.rglob('syscalls_BIN_*') if d.is_dir()
                     for f in d.iterdir() if f.name != 'binary_syscalls.txt'}
    base_bin_names = {base(p) for p in base_bins} | analysed_bins
    base_libs = {p for p in read_paths(f_libs) if is_lib(p)}
    base_lib_names = {base(p) for p in base_libs}
    base_jars = read_paths(f_jars)
    # libraries the static analysis covers although discovery did not see them loaded (ldd closure)
    analysed_libs = {lib_stem(f.name) for pat in ('syscalls_output_*', 'syscalls_unanalysed_*')
                     for d in root.rglob(pat) if d.is_dir() for f in d.iterdir() if '.so' in f.name}

    # --- diff. Binaries are compared by file name: discovery lists them as invoked
    # (/usr/bin/awk, /bin/sh) and the analysis by their real name (mawk, dash).
    rows, new = [], {'binaries': [], 'libs': [], 'jars': []}
    for p in sorted(bins):
        is_new = base(p) not in base_bin_names
        if is_new:
            new['binaries'].append(p)
        rows.append(('binary', p, 'new' if is_new else 'known', f'first process: {bins[p]}'))
    for p in sorted(libs):
        notes = []
        if p in base_libs:
            status = 'known'
        elif base(p) in base_lib_names:
            status = 'known'
            notes.append('same file name as a discovered library, different path')
        else:
            status = 'new'
            new['libs'].append(p)
            if TEMP_RE.match(p):
                notes.append('temporary path (name may change between runs)')
            if lib_stem(p) in analysed_libs:
                notes.append('covered by the static analysis (dependency closure)')
        rows.append(('library', p, status, '; '.join(notes)))
    for p in sorted(jars):
        is_new = p not in base_jars
        if is_new:
            new['jars'].append(p)
        rows.append(('jar', p, 'new' if is_new else 'known', ''))

    for kind, obs in (('binaries', bins), ('libs', libs), ('jars', jars)):
        pathlib.Path(f'{a.out}.observed_{kind}.txt').write_text(''.join(p + '\n' for p in sorted(obs)))
        pathlib.Path(f'{a.out}.new_{kind}.txt').write_text(''.join(p + '\n' for p in new[kind]))
    with open(a.out + '.artifacts.tsv', 'w') as fh:
        fh.write('kind\tpath\tstatus\tnotes\n')
        fh.writelines('\t'.join(r) + '\n' for r in rows)
    summary = {
        'n_binaries': len(bins), 'n_new_binaries': len(new['binaries']),
        'n_libs': len(libs), 'n_new_libs': len(new['libs']),
        'n_jars': len(jars), 'n_new_jars': len(new['jars']),
        'baseline_binaries': len(base_bin_names), 'baseline_libs': len(base_libs), 'baseline_jars': len(base_jars),
        'containers': ','.join(sorted(seen_cids)), 'note': note or '-',
    }
    pathlib.Path(a.out + '.artifacts.summary').write_text(''.join(f'{k}={v}\n' for k, v in summary.items()))
    if note:
        print(f'note: {note}')
    print(f"artifacts: binaries {len(bins)} ({len(new['binaries'])} new), libraries {len(libs)} "
          f"({len(new['libs'])} new), jars {len(jars)} ({len(new['jars'])} new)"
          + (f"  NEW: {' '.join(new['binaries'] + new['libs'])}" if new['binaries'] or new['libs'] else ''))


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
    d.add_argument('--runtime', nargs='*', default=[])
    d.add_argument('--out', required=True)
    r = sub.add_parser('artifacts')
    r.add_argument('--files', required=True)
    r.add_argument('--execve', required=True)
    r.add_argument('--match', required=True)
    r.add_argument('--injected')
    r.add_argument('--sources-dir', required=True)
    r.add_argument('--out', required=True)
    a = ap.parse_args()
    {'trace': cmd_trace, 'diff': cmd_diff, 'artifacts': cmd_artifacts}[a.cmd](a)


if __name__ == '__main__':
    main()
