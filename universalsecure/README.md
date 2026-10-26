# Universalsecure

Universalsecure is a local-first, read-only source review CLI. It scans a folder you select, reports a small set of security-relevant code patterns, and writes Markdown or JSON only when you ask it to.

The first release is intentionally offline: it does not execute project code, launch PentAGI or Strix, contact targets, or send source files anywhere. Its findings are heuristics for human review, not proof that a vulnerability exists.

## Quick start

Requires Python 3.10 or newer. The scanner uses only the Python standard library.

```bash
git clone --recurse-submodules https://github.com/shiva211-bot/Universalsecure.git
cd Universalsecure
python -m venv .venv
```

Activate the environment:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Run the module against a project you own or are authorized to review:

```bash
python -m universalsecure.cli scan /path/to/your/project
```

Save a report without overwriting an existing file:

```bash
python -m universalsecure.cli scan /path/to/your/project --format markdown --output review.md
python -m universalsecure.cli scan /path/to/your/project --format json --output review.json
```

The report path is relative to your current directory unless you provide an absolute path. To replace an existing report, pass `--force`.

Optional: `python -m pip install -e .` installs the `universalsecure` console command.

## Current checks

- Likely credential literals in source files. Credential values are redacted from report evidence.
- Dynamic `eval` / `exec` use.
- Subprocess calls with `shell=True`.
- TLS verification explicitly disabled.
- SQL execution built from an f-string or apparent string concatenation.
- Dynamic HTML insertion patterns such as `innerHTML` and `dangerouslySetInnerHTML`.

These checks are deliberately narrow. They can miss issues and can flag safe code; review each finding in context.

## Scan boundaries

- The scanner reads supported source and configuration files under the selected directory.
- It does not follow symlinks and skips common generated/dependency folders.
- It skips `.env*`, credential-named files, and files larger than 1 MB.
- It does not execute commands, install project dependencies, perform network requests, or modify scanned files.
- By default, only high-severity findings make the command return a non-zero exit code. Use `--fail-on never` to disable that behavior.

## Upstream projects

See [UPSTREAMS.md](UPSTREAMS.md) for the three source projects. They are pinned as Git submodules under `upstreams/`, so their source and licenses stay separate from this wrapper.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

No license has been assigned to Universalsecure yet. The upstream projects keep their own licenses and terms.
