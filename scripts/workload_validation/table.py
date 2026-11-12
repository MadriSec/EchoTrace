#!/usr/bin/env python3
"""Print the workload validation results as the paper's LaTeX table
(tables/policy-validation.tex, Table "Workload validation on the primary
containers").

One row per container, read from the results folder written by
workload_validation.sh:

  Container | Benchmark | Syscalls (missing / performed / permitted) | New

  performed  distinct syscalls the container made in the baseline run
             (allow-all filter, nothing enforced)
  missing    performed syscalls that are not in the SysJava policy
  permitted  syscalls in the SysJava policy
  New        binaries executed / native libraries opened in the baseline run
             that SysJava's startup discovery did not see ("---" when the
             run did not record them, i.e. sysdig was not available)

A container with several benchmarks (JRuby) gets one row: performed and
missing, and the new binaries and libraries, are the union over its
benchmarks (see --per-test).

Only containers that have results are listed. Benchmarks that fail even
without a policy are left out and named in a LaTeX comment, since their
trace does not describe a working benchmark (see --all).

Usage:
  scripts/workload_validation/table.py [RESULTS_DIR] [-o FILE] [--per-test] [--all]

RESULTS_DIR defaults to workload_validation_runs/results.
"""
import argparse
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from report import ROOT, rows  # noqa: E402

# Row order and display names, as in the paper.
ORDER = ['zookeeper', 'tomcat', 'cassandra', 'jetty', 'storm', 'orientdb',
         'elasticsearch', 'solr', 'groovy', 'jruby']
NAMES = {'jruby': 'JRuby', 'orientdb': 'OrientDB'}
IMAGE_SUFFIX = '-jdk8-buster'
PENDING = '---'

HEADER = r'''\begin{table}[t]
\centering
\caption{Workload validation on the primary containers.
\emph{Syscalls}: missing / performed / permitted counts. Performed calls
are observed in the baseline run; missing calls are those absent from
the policy. \emph{New}: binaries / libraries absent from startup discovery.
All counts are distinct; ``---'' denotes pending measurements.
\label{tab:policy-validation}}
\small
\setlength{\tabcolsep}{3pt}
\begin{tabular*}{\columnwidth}{@{\extracolsep{\fill}}llcc@{}}
\toprule
\textbf{Container} & \textbf{Benchmark} & \textbf{Syscalls} & \textbf{New} \\
\midrule'''
FOOTER = r'''\bottomrule
\end{tabular*}
\end{table}'''


def tex(s):
    for a, b in (('\\', r'\textbackslash{}'), ('_', r'\_'), ('%', r'\%'), ('&', r'\&'), ('#', r'\#')):
        s = s.replace(a, b)
    return s


def container(subject, image):
    tag = image.split(':', 1)[1] if ':' in image else ''
    tag = tag[:-len(IMAGE_SUFFIX)] if tag.endswith(IMAGE_SUFFIX) else tag
    return f'{NAMES.get(subject, subject.capitalize())} {tag}'.strip()


def benchmark(tests):
    if len(tests) == 1:
        return tests[0]
    prefix = os.path.commonprefix(tests)
    return f'{prefix}* ({len(tests)} tests)' if prefix else f'{len(tests)} tests'


def count(s):
    return PENDING if s is None else str(len(s))


def line(name, bench, missing, performed, permitted, new_bins, new_libs):
    return (f'{tex(name)} & {tex(bench)} & {len(missing)} / {len(performed)} / {len(permitted)}'
            f' & {count(new_bins)} / {count(new_libs)} \\\\')


def union(sets):
    """Union of the recorded sets; None if no benchmark recorded any."""
    sets = [s for s in sets if s is not None]
    return set().union(*sets) if sets else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('results', nargs='?', default=ROOT / 'workload_validation_runs' / 'results', type=pathlib.Path)
    ap.add_argument('-o', '--out', type=pathlib.Path, help='write the table to FILE instead of stdout')
    ap.add_argument('--per-test', action='store_true', help='one row per benchmark instead of one per container')
    ap.add_argument('--all', action='store_true', help='keep benchmarks that fail without a policy')
    a = ap.parse_args()
    if not a.results.is_dir():
        ap.error(f'results folder not found: {a.results}')

    kept, notes = {}, []
    for r in rows(a.results):
        if r['test'] == '-':
            notes.append(f"left out: {r['subject']}: {r['workload_run']}")
        elif 'n_sysjava' not in r:
            notes.append(f"left out: {r['subject']} / {r['test']}: no trace (baseline run: {r['workload_run']})")
        elif r['workload_run'] != 'pass' and not a.all:
            notes.append(f"left out: {r['subject']} / {r['test']}: baseline run without a policy: {r['workload_run']}")
        else:
            kept.setdefault(r['subject'], []).append(r)

    body = []
    for subject in sorted(kept, key=lambda s: (ORDER.index(s) if s in ORDER else len(ORDER), s)):
        rs = kept[subject]
        name = container(subject, rs[0]['image'])
        sets = [(r['test'], set(r['missing'].split()), set(r['workload_syscalls'].split()),
                 set(r['sysjava_syscalls'].split()),
                 *(set(r[k].split()) if k in r else None for k in ('new_binaries', 'new_libs'))) for r in rs]
        if a.per_test:
            body += [line(name if i == 0 else '', *s) for i, s in enumerate(sets)]
            continue
        tests = [s[0] for s in sets]
        missing = set().union(*(s[1] for s in sets))
        new_bins, new_libs = union(s[4] for s in sets), union(s[5] for s in sets)
        body.append(line(name, benchmark(tests), missing, set().union(*(s[2] for s in sets)), sets[0][3],
                         new_bins, new_libs))
        notes.append(f"{subject}: {', '.join(tests)}; missing: {' '.join(sorted(missing)) or '(none)'}")
        for label, new in (('new binaries', new_bins), ('new libraries', new_libs)):
            if new is not None:
                notes.append(f"{subject}: {label}: {' '.join(sorted(new)) or '(none)'}")

    out = [f'% Generated by scripts/workload_validation/table.py from {a.results.name}/']
    out += [f'% {n}' for n in notes] + [HEADER] + body + [FOOTER]
    text = '\n'.join(out) + '\n'
    if a.out:
        a.out.write_text(text)
        print(f'wrote {a.out}', file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
