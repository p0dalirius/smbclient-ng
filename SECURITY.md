# Security Policy

## Supported Versions

The project follows a "latest minor only" support model. Security fixes are provided for the most recent minor release line only.

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| < 3.0   | :x:                |

If you are on an older series, please upgrade to the latest `3.x` release to receive security updates.

## Reporting a Vulnerability

Please do not disclose security issues publicly. Instead, use one of the private channels below:

- Preferred: Report via GitHub Security Advisories using the "Report a vulnerability" form.
  - [Report a vulnerability on GitHub](https://github.com/p0dalirius/smbclient-ng/security/advisories/new)
- If you cannot use GitHub Advisories, you may contact the maintainer through the contact methods listed on their GitHub profile.

When reporting, please include as much detail as possible:
- Affected version(s) of `smbclientng` and your Python version
- Environment and OS details
- Reproduction steps and a minimal proof-of-concept, if available
- Impact assessment (e.g., confidentiality/integrity/availability)
- Any known mitigations or workarounds

## Our Response Process and Timelines

We aim to adhere to the following timelines:
- Acknowledgement of receipt: within 3 business days
- Initial triage and severity assessment: within 7 business days
- Remediation plan communicated: within 14 business days after triage
- Fix release: as soon as reasonably possible, typically within 90 days depending on complexity and severity

These timelines are targets, not guarantees, but we will keep you updated throughout the process.

## Disclosure Policy

- We follow a coordinated disclosure approach. Please refrain from public disclosure until a fix is available and users have had a reasonable opportunity to update.
- We generally request up to a 90-day embargo window for complex issues. Shorter or longer timelines may be agreed case-by-case based on severity and exploitability.
- Credit: We are happy to credit reporters in release notes and advisories if you wish. Please indicate your preferred attribution.

## Scope

In scope:
- The `smbclientng` Python package and CLI tool in this repository
- Configuration and logic implemented within this codebase

Out of scope (report upstream instead):
- Vulnerabilities that only affect third-party dependencies (e.g., `impacket`, `rich`, etc.)
- Issues that arise solely from misconfiguration or unsupported environments

## Security Fix Delivery

- Security fixes will be released as patch releases to the latest supported minor line (`3.x`).
- Release notes and, when applicable, a security advisory will describe the impact, affected versions, and upgrade instructions.

Thank you for helping keep `smbclient-ng` and its users secure.
