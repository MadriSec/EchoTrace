# Third-Party Notices

EchoTrace is licensed under the GNU General Public License v3.0. This file summarizes major third-party components used or invoked by the project. It is not a replacement for the upstream license texts.

## SysPartCode

- Repository: https://github.com/vidyalakshmir/SysPartCode/tree/optimizations
- Local path: `SysPartCode/`
- License: GNU General Public License v3.0, see `SysPartCode/LICENSE`
- Usage: EchoTrace invokes SysPart for static syscall reachability over container-extracted ELF libraries and binaries.

## Sysdig

- Repository: https://github.com/draios/sysdig
- Usage: Dynamic container capture through `sysdig --modern-bpf`
- License: See the upstream Sysdig repository for current licensing terms.

## Java Analysis Libraries

EchoTrace uses Java bytecode/static-analysis libraries declared in `pom.xml`, including ASM and SootUp. See `pom.xml` and the upstream projects for exact dependency versions and license terms.

## Python ELF Tooling

EchoTrace uses `pyelftools` for ELF parsing in helper scripts. See the upstream pyelftools project for its license terms.

## Container and Seccomp Tooling

EchoTrace uses Docker-compatible seccomp profile formats and Docker CLI workflows. Docker itself is not bundled in this repository.
