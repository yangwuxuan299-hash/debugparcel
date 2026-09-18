# Security policy

DebugParcel handles potentially sensitive diagnostics. Please avoid placing real credentials, customer data, or unredacted artifacts in public issues.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature when it is available for this repository. Include:

- the affected version or commit;
- a minimal synthetic reproduction;
- the sensitive-data class that may escape redaction; and
- whether the issue can affect an exported parcel.

Please do not publish a proof of concept containing live secrets. Maintainers should acknowledge a report within seven days and provide a remediation timeline after validation.

## Scope

High-priority reports include:

- source values surviving the export audit;
- original files or reverse mappings appearing in a parcel;
- screenshot masks not being burned into output pixels;
- unexpected network transmission or persistent storage of imported data; and
- crafted input causing unsafe fallback to the original artifact.
