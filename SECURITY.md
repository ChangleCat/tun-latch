# Security Policy

## Supported versions

Only the current `main` branch is supported. The project has no stable release yet and does not
provide a production firewall or leak-protection guarantee.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

<https://github.com/ChangleCat/tun-latch/security/advisories/new>

Reports in Chinese or English are welcome.

Do **not** open a public issue for a suspected vulnerability. If the private entry point is
unavailable, contact the maintainer through the GitHub profile
[@ChangleCat](https://github.com/ChangleCat) without posting details publicly.

Please include:

- the affected commit or branch;
- macOS version and architecture;
- a minimal reproduction or reasoning;
- the expected and observed behavior;
- relevant logs with secrets, local paths, PIDs, and packet captures removed.

## Scope

Reports are welcome for:

- IPC framing, length limits, peer checks, and socket/path validation;
- configuration, draft, policy, and capture parsing;
- permission and ownership checks around private files and endpoints;
- resource bounds, task shutdown, and recovery-state handling;
- the reviewed `unsafe` adapter in `tunlatch-platform/src/identity/native.rs`;
- privilege-boundary or authorization mistakes.

The current version is a read-only observer. It does not open `/dev/pf`, call `pfctl`, change
routes, install a service, or provide real leak protection. "PF enforcement is missing" and
"protection is reported unknown" are documented limitations, not vulnerabilities.

## Safe harbor

- Test only on a Mac and data you own or are authorized to use.
- Do not run real PF, root, install, reboot, or network-changing experiments for a report. Code
  review and offline analysis are enough.
- Do not access other people's data, disrupt networks, or test third-party systems.
- Give the maintainer reasonable time to fix the issue before public disclosure.

## Response

This is a personal project without a bug bounty. Reports are handled on a best-effort basis:
acknowledgement, triage, a fix or mitigation, and coordinated disclosure. Credit is offered on
request.

## Please do not

- paste root paths, session names, PIDs, credentials, packet captures, or operator evidence into a
  public issue;
- open a public issue containing exploit details;
- publish a working exploit before a fix is available.
