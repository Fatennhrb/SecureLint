# Releasing SecureLint

SecureLint is published to PyPI by the [Release](../.github/workflows/release.yml)
workflow, with PyPI's **Trusted Publishing**: GitHub proves to PyPI which
repository and workflow is asking, so no password or token is stored
anywhere, not even as a GitHub secret. Every release also gets PEP 740
digital attestations, which let anyone check that a file on PyPI was built
by this workflow.

## One-time setup

Done once, on the websites, by the maintainer.

### 1. Accounts

Create an account on [pypi.org](https://pypi.org/account/register/) and one
on [test.pypi.org](https://test.pypi.org/account/register/) (they are
separate). Both require two-factor authentication; an authenticator app or a
security key works.

### 2. A "pending publisher" on each

A pending publisher tells PyPI: "the first upload of this project name, from
this workflow, is allowed". It does not reserve the name: someone else could
still take `securelint` first, so do this shortly before the first release.

On **test.pypi.org**, then on **pypi.org**: account menu > **Publishing** >
add a pending publisher for **GitHub**, with:

| Field | test.pypi.org | pypi.org |
|-------|---------------|----------|
| PyPI project name | `securelint` | `securelint` |
| Owner | `Fatennhrb` | `Fatennhrb` |
| Repository name | `SecureLint` | `SecureLint` |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `testpypi` | `pypi` |

The environment name must be exactly the one the workflow's job uses.

### 3. Protect the `pypi` environment on GitHub

The workflow creates the `testpypi` and `pypi` environments the first time
it runs. In the repository: **Settings > Environments > pypi**:

- **Required reviewers**: add yourself, so a real release waits for a click.
- **Deployment branches and tags**: allow only tags matching `v*`.

## A rehearsal (TestPyPI only)

**Actions > Release > Run workflow** on `main`. It builds the package and
publishes it to TestPyPI only. A version already on TestPyPI is skipped, so
the rehearsal can be run again. To try the result:

```console
pip install --index-url https://test.pypi.org/simple/ securelint
```

(TestPyPI is a test site: it is not a place to install real tools from.)

## A release

1. Set the version in `src/securelint/__init__.py`, move "Unreleased" in
   `CHANGELOG.md` to the new version, and commit.
2. Push, and wait for CI to pass on that commit.
3. Tag it and push the tag:

   ```console
   git tag -a v1.0.0 -m "SecureLint 1.0.0"
   git push origin v1.0.0
   ```

4. The workflow builds, checks that the tag matches the package version,
   publishes to TestPyPI, then waits for your approval on the `pypi`
   environment. Approve it in the workflow run to publish to PyPI.
5. Create the GitHub release page from the tag, with the changelog's text.

A version published on PyPI can never be published again, even after being
deleted: a mistake means a new version number.
