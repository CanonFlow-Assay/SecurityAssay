# Approved local tools and database

Evaluation and provisioning are separate operations. The committed toolchain lock
pins Linux/amd64 Gitleaks 8.30.1, Syft 1.55.0, Grype 0.121.0, their binary/config
hashes, the immutable local Docker image ID, and every DB file. This phase-2 candidate pins a separate schema v6.1.10 database built
2026-10-28T06:23:30Z; the phase-1 checkout and 22 October bundle remain preserved. It is about 3.1 GiB and intentionally
not committed to Git. The pinned ASVS catalog and its license are in `standards/`.

## Provision a fresh bundle

Download only the exact official Linux archives in `Provisioning.Approved` into
`<bundle>/downloads/{gitleaks,syft,grype}.tar.gz`. Retain the official release
checksum files. The C# provisioner independently requires their committed SHA-256
values and extracts only each expected regular binary, rejecting duplicates.
It never executes target application/package code or an arbitrary install script.

Provision a local schema-6 database using the approved Grype binary and explicit
configuration, with its cache under `<bundle>/db`. This is the online operation:

```sh
GRYPE_DB_CACHE_DIR=/absolute/bundle/db GRYPE_CHECK_FOR_APP_UPDATE=false \
  /absolute/bundle/bin/grype --config policies/scanners/grype.yaml db update
```

The initially verified binary may be extracted from its checksum-verified
official archive before this step. Provision into a fresh directory; do not
update an active pinned bundle during evaluation. Keep its official database
import metadata, archive URL/checksum and all cache files. No live DB query can
be release authority.

Then run:

```sh
dotnet src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll provision \
  /absolute/SecurityAssay /absolute/bundle
```

It verifies archives/binaries, installs the repository's approved configuration,
records DB status/file hashes, builds a scratch image locally with networking
disabled, and writes `policies/toolchain.lock.json`, `m0.json` and
`full-release.json`. This deliberately changes policy pins: inspect and commit
them before source-bound qualification. It does not grant automatic approval.
Use an existing matching bundle for repeat evaluations; do not reprovision
between deterministic comparisons.

## Offline execution boundary

Each scanner container uses the exact image ID with `--pull=never`, `--network
none`, non-root UID/GID, a read-only root filesystem, all capabilities dropped,
no-new-privileges and CPU/memory/PID limits. Before start the adapter inspects
actual network/read-only/user/capability/resource settings. Only a declared-byte
snapshot, approved configuration and (for Grype) SBOM/database are mounted
read-only. No host home, credential files or Docker socket enters a scanner.
Temporary snapshots retain a private host parent while allowing the container
to read the mounted child. Cleanup removes the owned container after timeout.

The host, Docker daemon, evaluation clock/input and reviewed policy are trusted
infrastructure. This does not claim protection from a hostile privileged host.
Future DB/tool updates require new pins and qualification; old results retain
their original identities and declared times.

Primary sources: [Gitleaks](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1),
[Syft](https://github.com/anchore/syft/releases/tag/v1.55.0),
[Grype](https://github.com/anchore/grype/releases/tag/v0.121.0),
[database documentation](https://oss.anchore.com/docs/guides/vulnerability/database/).

## Astra current-time candidate

The isolated `SecurityAssay-Astra-Phase2` branch uses the unchanged approved scanner versions and fresh database bytes under `~/.cache/securityassay-astra-20261029`. The old `~/.cache/securityassay-m0` bundle was not modified. Online database provisioning and pin generation are separate from offline evaluation.

Qualification accepts an explicit ISO UTC evaluation instant, recorded in its journal:

```sh
dotnet src/SecurityAssay/bin/Release/net11.0/SecurityAssay.dll qualify \
  /absolute/SecurityAssay-Astra-Phase2 /absolute/approved-bundle \
  /absolute/native-net11-rc1/cs-assay.dll 2026-10-29T06:45:00Z \
  /absolute/SecurityAssay-Astra-Phase2/artifacts/current-qualification
```

Omitting the instant uses current UTC; it no longer replays a hardcoded 23 October time. Historical qualification records retain their old source/policy/time identities. Current-time Pass remains scoped M0 evidence and grants no human or production approval.
