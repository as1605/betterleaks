# Publishing Guide & PyPI Trusted Publishing Setup

The `betterleaks` Python package (shipping both the Python bindings and the `betterleaks` CLI executable) is published to **PyPI** via **OpenID Connect (OIDC) Trusted Publishing** with **PEP 740 digital attestations**.

GitHub Actions requires workflow definitions to reside in `.github/workflows/`, and PyPI Trusted Publishers validate against a workflow filename inside `.github/workflows/`.

---

## 1. PyPI Trusted Publisher Configuration

Configure a Trusted Publisher on [PyPI Account Publishing Settings](https://pypi.org/manage/account/publishing/):

1. Log in to the `betterleaks` PyPI project account.
2. Navigate to **Your projects** -> `betterleaks` -> **Publishing** (or **Account Settings** -> **Publishing** for a pending publisher).
3. Under **"Add a publisher"**, select **GitHub** and fill in:
   - **PyPI Project Name**: `betterleaks`
   - **Owner**: `betterleaks`
   - **Repository name**: `betterleaks`
   - **Workflow name**: `python-release.yml`
   - **Environment name**: `pypi`
4. Click **"Add"**.

---

## 2. GitHub Repository Environment

In `betterleaks/betterleaks` -> **Settings** -> **Environments**, create an environment named **`pypi`**.

---

## 3. Release Flow

The Python package starts at `2.0.0` (while embedding the latest `v2.*` Go engine version in `__upstream_version__` and the CLI `--version` flag).

1. Pushing a tag matching `python-v*` (e.g. `python-v2.0.0`) triggers `.github/workflows/python-release.yml` (or run manually via `workflow_dispatch` with a PEP 440 `version` input like `2.0.0`).
2. The workflow stamps `_version.py`, builds and tests platform wheels across macOS, Linux, and Windows plus the source distribution, and publishes them to PyPI via `pypa/gh-action-pypi-publish` with `attestations: true`.
