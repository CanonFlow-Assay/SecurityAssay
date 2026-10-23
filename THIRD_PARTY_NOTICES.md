# Third-party evidence/tool material

- `standards/asvs-5.0.0/catalog.json`: unmodified OWASP ASVS 5.0.0 English JSON,
  OWASP ASVS contributors, CC BY-SA 4.0. Full license and source attribution are
  beside the catalog. Requirement mappings do not imply endorsement/certification.
- `policies/scanners/gitleaks.toml`: Gitleaks v8.30.1 default configuration, MIT;
  source https://github.com/gitleaks/gitleaks/tree/v8.30.1/config . Its full
  upstream license is included in `GITLEAKS-LICENSE.txt`.
- Scanner executables remain in the local ignored provisioned bundle, not Git.
  Gitleaks is MIT; Syft/Grype are Apache-2.0. Original official release archives
  and their checksums remain with the provisioned tools; retain their notices
  if redistributing a scanner bundle/image. No binaries are publicly published.
- Sample package locks are declared metadata for synthetic controls. Their
  package code is not included or executed. See `samples/NOTICE.md`.

SecurityAssay/CanonFlow evidence source code is Apache-2.0 under LICENSE.
