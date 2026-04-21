# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x (beta) | :white_check_mark: |

W3GathrVulns is currently in beta. Security fixes are applied to the latest version only.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report them privately by email: **inimzil.pro@gmail.com**

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (optional)

I will respond as soon as I can.

If the vulnerability is confirmed, a fix will be prioritised and a patched release issued. You will be credited in the release notes unless you prefer to remain anonymous.

## Scope

In scope:
- Authentication and authorisation bypasses
- API token exposure or mishandling
- SQL injection, XSS, SSRF, RCE
- Sensitive data exposure (findings, tokens, credentials)
- Insecure default 
- Any other thing related to project codebase and/or configurations

Out of scope:
- Issues in dependencies not directly exploitable/related to this project
