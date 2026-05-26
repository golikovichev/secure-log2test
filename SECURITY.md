# Security Policy

`secure-log2test` reads Kibana JSON exports and writes pytest modules. The redaction layer is the part most users care about: auth headers and secret-looking body fields get replaced with `***REDACTED***` before they reach the output file. That output is usually committed to a public or shared repo, so a redaction miss has real impact.

If you find a way to bypass the redaction, please report it privately. Do not open a public issue.

## Supported versions

| Version | Status |
| ------- | ------ |
| 1.0.x   | Supported, receives security fixes |
| < 1.0   | Not supported |

## Reporting a vulnerability

Use GitHub Security Advisories (Private vulnerability reporting) on this repo:

https://github.com/golikovichev/secure-log2test/security/advisories/new

That keeps the report private until a fix ships. If you cannot use that channel, open an empty issue titled `security: contact request` and I will reach out.

## What counts

In scope:

- Auth header values leaking past redaction (Authorization, Cookie, X-API-Key, similar)
- Secret-looking body fields surviving the field-name and value-pattern passes (token, password, api_key, refresh_token, similar)
- Generated test code that executes attacker-controlled input from the source Kibana export
- Path traversal or arbitrary file write in the output path handling

Out of scope:

- A Kibana export that contains secrets in fields the tool was never told about (file a feature request instead)
- Issues in pytest, requests, or other dependencies (report those upstream)
- Self-DoS by feeding a 50 GB export file

## Response timeline

I will acknowledge a report within 5 working days. A fix for a confirmed redaction bypass ships within 30 days, faster if the impact is severe. Once a fix is public I will credit the reporter in the release notes unless they prefer to stay anonymous.

## Past disclosures

None yet.
