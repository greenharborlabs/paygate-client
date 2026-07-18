# Releasing `paygate-client`

This project publishes only with PyPI Trusted Publishing. Do not create a PyPI
API token, add one as a GitHub secret, upload GitHub release assets, retag a
release, overwrite a package, or delete an immutable release/package to retry.

## One-time external setup

1. In PyPI, create (or ask a PyPI administrator to create) a pending publisher
   for project **`paygate-client`** with owner **`greenharborlabs`**, repository
   **`paygate-client`**, workflow file **`publish.yml`**, environment
   **`pypi`**, and no other workflow/environment tuple. This must be an exact
   match; use the PyPI project name, not the import package name.
2. In GitHub repository settings, create the protected environment named
   **`pypi`**. Require the release approvers required by the organization and
   restrict it to protected tags/releases as policy requires. Do not add PyPI
   credentials to the environment.
3. Protect `main` and the `v*` tag namespace so only the release process can
   create release tags. The workflow verifies that the tag commit is in
   `origin/main` after resolving the annotated release tag itself.

The pending-publisher setup is sufficient for the first release. Do not create
the PyPI project manually unless PyPI support directs it; a Trusted Publishing
first upload creates it after the exact tuple has been configured.

## Name preflight and first release

Before preparing a release, check whether the normalized name is available:

```sh
if ! status="$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' https://pypi.org/pypi/paygate-client/json)"; then
  echo "PyPI name check request failed" >&2
  exit 1
fi

case "$status" in
  404) echo "paygate-client is currently available on PyPI" ;;
  200) echo "paygate-client is already claimed on PyPI; stop" >&2; exit 1 ;;
  *) echo "Unexpected PyPI response status: $status; stop" >&2; exit 1 ;;
esac
```

This check uses no credentials. HTTP 404 means the name is currently available;
HTTP 200 means it is already claimed, so stop and confirm ownership before
publishing. Any other status is an error, so stop. Also inspect
https://pypi.org/project/paygate-client/ for confusingly similar ownership.

For a first release, merge the release-ready commit to `main`, choose a new
version in `paygate_client/__init__.py`, and create an annotated `vX.Y.Z` tag
at that exact commit. Record the tag commit with `git rev-parse vX.Y.Z^{commit}`
and create the GitHub Release for that existing tag. The workflow fetches the
tag, requires it to be annotated, resolves `refs/tags/vX.Y.Z^{commit}`, and
verifies that immutable commit is contained in `origin/main`. GitHub ignores a
Release API `target_commitish` when the tag already exists, so it is not used as
release provenance.

The workflow checks full history, a clean checkout, immutable GitHub release
tag resolution, main ancestry, `vX.Y.Z` matching wheel and sdist metadata,
strict distribution metadata, and clean installs of both the wheel and sdist.
It preflights PyPI without credentials: a project 404 is valid for the first
release, while an existing target version or normalized-name conflict fails
before publishing. It produces one of each plus a
SHA-256 manifest, transfers them as a retained workflow artifact, verifies the
manifest again, then requests OIDC only in the protected `pypi` job. PyPI
attestations are requested by the publishing action.

## Dry runs, approvals, and retries

Use **Run workflow** with a ref to exercise build, validation, artifact
transfer, and manifest generation. A manual run can never enter the `publish`
job and therefore cannot request an OIDC token or upload to PyPI.

On a real `release.published` event, approve the protected `pypi` environment
only after reviewing the release tag, its resolved commit SHA, version, CI status, and the
`SHA256SUMS` workflow artifact. The job publishes precisely the downloaded,
re-verified files; it does not rebuild them or upload release assets.

If a check, OIDC exchange, hash comparison, or upload fails, stop. Inspect the
workflow logs and PyPI project files before any retry. A same-tag rerun is
allowed only for an external/transient failure when source, workflow, metadata,
and artifact bytes are identical **and PyPI accepted no files**. If any file
was accepted, or any source/workflow/metadata byte needs changing, make a
forward fix with a new version and a new `vX.Y.Z` tag/release. Never overwrite,
delete, or retag the failed immutable release.

For a partial upload, treat the version as consumed: verify the accepted file
hashes on PyPI, preserve the workflow artifact and logs, and issue a new
version. Escalate project-name ownership or pending-publisher mismatches to a
PyPI administrator rather than weakening the workflow or adding a token.
