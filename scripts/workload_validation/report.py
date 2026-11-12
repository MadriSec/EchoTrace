#!/usr/bin/env python3
"""Report the workload validation results of every subject.

For each subject and test in the results folder written by
workload_validation.sh, print and export:
  - the SysJava policy syscalls
  - the syscalls observed under the workload
  - the diff: missing (workload - SysJava), used (both), unused (SysJava - workload)
  - the binaries executed and native libraries opened under the workload that
    SysJava's startup discovery did not see (when recorded, see ARTIFACTS)
together with the outcome of the workload run (no restrictions) and of the
enforce run (under the SysJava policy).

Usage:
  scripts/workload_validation/report.py [RESULTS_DIR] [--csv FILE] [--summary]

--summary prints only the one-line-per-test overview table.

RESULTS_DIR defaults to workload_validation_runs/results; the CSV defaults to
RESULTS_DIR/report.csv. Syscall lists in the CSV are space-separated.
"""
import argparse
import csv
import pathlib
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]

COLUMNS = [
    'subject', 'test', 'image', 'workload_run', 'enforce_run',
    'n_sysjava', 'n_workload', 'n_missing', 'n_used', 'n_unused', 'pct_sysjava_used',
    'n_new_binaries', 'n_new_libs',
    'sysjava_syscalls', 'workload_syscalls', 'missing', 'used', 'unused',
    'new_binaries', 'new_libs',
    'invalid_policy_names',
]


def names(path):
    return sorted(l.strip() for l in path.read_text().splitlines() if l.strip()) if path.is_file() else None


def text(path, default='-'):
    return path.read_text().strip() if path.is_file() else default


def kv(path):
    if not path.is_file():
        return {}
    return dict(l.split('=', 1) for l in path.read_text().splitlines() if '=' in l)


def meta_image(sd):
    for l in text(sd / 'meta.txt', '').splitlines():
        if l.startswith('image: '):
            return l[len('image: '):]
    return '-'


def tests_of(sd):
    suffixes = ('.workload.status', '.enforce.status')
    return sorted({f.name[:-len(s)] for s in suffixes for f in sd.glob('*' + s)})


def rows(results):
    for sd in sorted(p for p in results.iterdir() if p.is_dir() and p.name != 'bin'):
        if (sd / 'skipped.txt').is_file():
            yield {'subject': sd.name, 'test': '-', 'workload_run': text(sd / 'skipped.txt')}
            continue
        for t in tests_of(sd):
            pre = sd / f'{t}.workload'
            missing, used, unused = (names(pathlib.Path(f'{pre}.{k}.txt')) for k in ('missing', 'used', 'unused'))
            workload = names(pathlib.Path(f'{pre}.observed.txt'))
            sysjava = sorted(set(used) | set(unused)) if used is not None and unused is not None else None
            row = {
                'subject': sd.name, 'test': t, 'image': meta_image(sd),
                'workload_run': text(sd / f'{t}.workload.status'),
                'enforce_run': text(sd / f'{t}.enforce.status'),
                'invalid_policy_names': kv(pathlib.Path(f'{pre}.summary')).get('invalid_policy_names', '-'),
            }
            for key, lst in (('sysjava', sysjava), ('workload', workload), ('missing', missing),
                             ('used', used), ('unused', unused)):
                if lst is not None:
                    row['n_' + key] = len(lst)
                    row[key if key in ('missing', 'used', 'unused') else key + '_syscalls'] = ' '.join(lst)
            for key in ('new_binaries', 'new_libs'):   # absent when not recorded
                lst = names(pathlib.Path(f'{pre}.{key}.txt'))
                if lst is not None:
                    row['n_' + key] = len(lst)
                    row[key] = ' '.join(lst)
            if sysjava:
                row['pct_sysjava_used'] = f'{100.0 * len(used) / len(sysjava):.1f}'
            yield row


def show(row):
    print(f"== {row['subject']} / {row['test']}")
    if row['test'] == '-':
        print(f"   {row['workload_run']}\n")
        return
    print(f"   image: {row.get('image', '-')}")
    print(f"   workload run (no restrictions): {row['workload_run']}    "
          f"enforce run (SysJava policy): {row['enforce_run']}")
    if 'n_sysjava' not in row:
        print('   no diff available (workload phase missing or trace failed)\n')
        return
    print(f"   {row.get('pct_sysjava_used', '-')}% of the SysJava policy was exercised by the workload")
    if row.get('invalid_policy_names', '-') != '-':
        print(f"   policy names that are not syscalls (ignored): {row['invalid_policy_names']}")
    for label, n, lst in (
        ('SysJava policy', 'n_sysjava', 'sysjava_syscalls'),
        ('Workload', 'n_workload', 'workload_syscalls'),
        ('Missing  (workload, not in SysJava)', 'n_missing', 'missing'),
        ('Used     (in both)', 'n_used', 'used'),
        ('Unused   (SysJava, not in workload)', 'n_unused', 'unused'),
        ('New binaries  (workload, not in startup discovery)', 'n_new_binaries', 'new_binaries'),
        ('New libraries (workload, not in startup discovery)', 'n_new_libs', 'new_libs'),
    ):
        if n not in row and n.startswith('n_new'):
            print(f"\n   {label}: not recorded")
            continue
        print(f"\n   {label}: {row.get(n, 0)}")
        body = row.get(lst, '') or '(none)'
        print(textwrap.fill(body, width=100, initial_indent='     ', subsequent_indent='     '))
    print()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('results', nargs='?', default=ROOT / 'workload_validation_runs' / 'results', type=pathlib.Path)
    ap.add_argument('--csv', type=pathlib.Path)
    ap.add_argument('--summary', action='store_true', help='print only the overview table')
    a = ap.parse_args()
    if not a.results.is_dir():
        ap.error(f'results folder not found: {a.results}')
    out = a.csv or a.results / 'report.csv'

    all_rows = list(rows(a.results))
    if not a.summary:
        for r in all_rows:
            show(r)

    width = max([len('image')] + [len(str(r.get('image', '-'))) for r in all_rows]) + 2
    print(f"{'subject':<14}{'image':<{width}}{'test':<24}{'workload':<10}{'enforce':<10}"
          f"{'sysjava':>8}{'workload':>9}{'missing':>8}{'used':>6}{'unused':>7}{'%used':>7}"
          f"{'newbin':>8}{'newlib':>7}")
    for r in all_rows:
        print(f"{r['subject']:<14}{str(r.get('image', '-')):<{width}}{r['test']:<24}"
              f"{str(r.get('workload_run', '-'))[:9]:<10}"
              f"{str(r.get('enforce_run', '-'))[:9]:<10}{r.get('n_sysjava', '-'):>8}{r.get('n_workload', '-'):>9}"
              f"{r.get('n_missing', '-'):>8}{r.get('n_used', '-'):>6}{r.get('n_unused', '-'):>7}"
              f"{r.get('pct_sysjava_used', '-'):>7}"
              f"{r.get('n_new_binaries', '-'):>8}{r.get('n_new_libs', '-'):>7}")

    with open(out, 'w', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS, restval='-')
        w.writeheader()
        w.writerows(all_rows)
    print(f'\nCSV: {out}')


if __name__ == '__main__':
    main()
