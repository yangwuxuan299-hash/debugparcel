# DebugParcel

**Privacy-first debug bundles for web bugs — HAR, console logs, and screenshots, sanitized locally.**

[Try the live app](https://debugparcel.wuxuanyang375.chatgpt.site)

DebugParcel turns the evidence behind a web bug into a reviewable ZIP without uploading the source files. It is built for support engineers, QA teams, frontend developers, and open-source maintainers who need useful diagnostics without casually sharing credentials or personal data.

## What it does

- Imports HAR files, console logs, and screenshots in the browser.
- Replaces matching values with consistent aliases across text artifacts.
- Detects authorization headers, cookies, API keys, JWTs, emails, IP addresses, internal hosts, user IDs, and local paths.
- Omits request and response bodies, including multipart parameters, by default.
- Sanitizes structured HAR query and cookie fields before producing request summaries.
- Lets the reporter burn permanent masks into screenshot pixels.
- Runs a final leak audit before export.
- Produces an issue-ready ZIP with a Markdown report, sanitized evidence, and SHA-256 checksums.

Nothing is sent to a server. Originals and the in-memory alias map disappear when the tab closes.

## Parcel format

```text
debugparcel-YYYYMMDD-HHMM.zip
├── report.md
├── network.sanitized.har
├── console.sanitized.json
├── screenshot.redacted.png
└── manifest.json
```

Files are included only when their source artifact was supplied. The manifest contains category totals and hashes of sanitized outputs; it never contains original values or a reverse alias map.

## Run locally

Requirements: Node.js 22.13 or newer.

```bash
npm ci
npm run dev
```

Then open the local URL printed by the development server. Use **Try safe demo** to exercise the complete flow without providing your own data.

For a production check:

```bash
npm run lint
npm test
npm run typecheck
npm run build
```

## Privacy model

DebugParcel is deliberately conservative:

- Request and response body text is replaced with omission markers.
- Screenshot masking uses opaque pixels rather than reversible blur.
- Export is blocked when a discovered source value survives the text audit.
- The final report and manifest pass through the same leak audit before ZIP creation.
- Raw values, bundle secrets, and reverse mappings are never written to the output.
- No data is stored in cookies, local storage, or a database.

Automated detection cannot guarantee that every sensitive value will be found. Reporters must review the sanitized preview and screenshot before downloading a parcel.

## Limitations

- Screenshot detection is manual; OCR is not part of v0.1.
- Very large inputs are capped at 50 MB per text artifact, 12 MB per screenshot, and 60 MB combined.
- Console files are treated as JSON when valid and as plain text otherwise.
- JSON with a HAR envelope is rejected from the console slot and must be imported as a network archive.
- Redaction prioritizes safe output over preserving request or response bodies.

## v0.1.5 review and import hardening

This release rejects mislabeled or malformed HAR data before export, detects percent-encoded copies of known values during the final privacy audit, makes custom rules encoding-aware without corrupting generated aliases, and removes a redundant full HAR clone. Truncated previews can now be downloaded in full for local review, every in-progress parcel can be cleared immediately, muted text meets AA contrast, and builds verify the hosted artifact contract before publication.

## v0.1.1 hardening

This release closes HAR path, cookie, query, multipart, JSON-key, and serialized-string audit gaps; adds regression fixtures; moves text scanning into a Web Worker; validates screenshot signatures and decoded dimensions; improves touch and keyboard masking; and makes both sanitized text artifacts reviewable before export.

## v0.1.4 hosted asset routing

This patch routes application JS, CSS, and the sanitizer Web Worker through the final Worker response even on asset-first hosts, so security headers and successful-response-only immutable caching are enforced consistently.

## v0.1.3 hosting compatibility

This patch applies the privacy-focused Content Security Policy and related browser security headers at the final Worker response, request proxy, and static asset layers. Hashed bundles keep immutable browser caching, including on hosts that ignore `_headers` metadata.

## v0.1.2 deployment hardening

This patch moved the browser security policy from static metadata to the application request layer so hosted HTML responses receive it reliably.

## Roadmap

- Optional browser extension capture
- Rule packs for common SaaS and cloud credentials
- Streaming parsing for traces larger than the current browser-safety limits
- Importable organization policies
- Reproducible CLI mode for CI and support tooling

## Security

Please do not attach real secrets to public issues. See [SECURITY.md](SECURITY.md) for private vulnerability reporting guidance.

## License

MIT
