# SOC2 Compliance Checker

AI-powered compliance verification for pull requests. An agent investigates each PR — checking ticket traceability, documentation, test coverage, and review tool findings — then posts a live progress comment with a confidence score.

## Features

- **Ticket traceability** — verifies PR references valid Linear tickets
- **Documentation checks** — ensures issue and spec files exist and align with code
- **Test coverage** — flags changed source files without corresponding tests
- **Review tool gate** — waits for CodeRabbit/Aikido/Greptile and checks for unresolved findings
- **Confidence scoring** — 0–100% score with configurable pass threshold
- **Live PR comments** — updates in real-time as the agent investigates
- **Exempt mode** — lightweight audit for trivial changes via `compliance:exempt` label

## How It Works

```
PR Opened/Updated/Labeled
       │
       ▼
AI agent starts investigating (Gemini 2.0 Flash)
       │
       ├──► git diff stat → scope the changes
       ├──► Extract ticket IDs → verify in Linear
       ├──► Check issues/*.md and specs/*.md
       ├──► Find test files for changed source
       ├──► Wait for review bots → check findings
       │
       ▼
Post compliance report with confidence score
       │
       ▼
Pass (≥ threshold) / Fail (< threshold)
```

## Usage

### 1. Add secrets to your repository

| Secret | Required | Description |
|--------|----------|-------------|
| `GEMINI_API_KEY` | Yes | Google Gemini API key |
| `LINEAR_API_KEY` | No | Linear API key for ticket verification |

### 2. Create workflow in your repository

Copy from [`examples/caller-workflow.yml`](examples/caller-workflow.yml):

```yaml
# .github/workflows/compliance.yml
name: SOC2 Compliance

on:
  pull_request:
    branches: [main, staging]
    types: [opened, synchronize, reopened, ready_for_review, labeled]

concurrency:
  group: compliance-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  compliance-check:
    if: github.event.pull_request.draft == false
    uses: dorkalev/soc2-compliance/.github/workflows/compliance-check.yml@main
    with:
      pr_body: ${{ github.event.pull_request.body }}
      pr_title: ${{ github.event.pull_request.title }}
      pr_author: ${{ github.event.pull_request.user.login }}
      pr_number: ${{ github.event.pull_request.number }}
      repo: ${{ github.repository }}
      ticket_pattern: "PROJ-[0-9]+"
      base_branch: main
      issues_path: issues
      specs_path: specs
      required_reviewers: "coderabbit,aikido,greptile"
      confidence_threshold: 70
      pr_labels: ${{ join(github.event.pull_request.labels.*.name, ',') }}
    secrets:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      LINEAR_API_KEY: ${{ secrets.LINEAR_API_KEY }}
      REPO_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 3. Configure branch protection

Add the compliance job as a required status check on your protected branches.

## Configuration

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `pr_body` | Yes | - | PR description text |
| `pr_title` | No | `""` | PR title |
| `pr_author` | No | `""` | PR author login |
| `pr_number` | Yes | - | PR number for commenting |
| `repo` | Yes | - | Repository (owner/name) |
| `ticket_pattern` | Yes | - | Regex for ticket IDs (e.g., `PROJ-[0-9]+`) |
| `base_branch` | No | `main` | Branch to diff against |
| `issues_path` | No | `issues` | Path to issue requirement files |
| `specs_path` | No | `specs` | Path to technical spec files |
| `linear_team_id` | No | - | Linear team ID for filtering |
| `required_reviewers` | No | `""` | Comma-separated review bots (e.g., `coderabbit,aikido,greptile`) |
| `confidence_threshold` | No | `70` | Minimum confidence % to pass (0–100) |
| `pr_labels` | No | `""` | Comma-separated PR labels (for `compliance:exempt` detection) |

## Exempt Mode (`compliance:exempt`)

For trivial changes that don't warrant full ticket traceability — CI config updates, dependency pins, typo fixes, formatting changes.

### How to use

1. Add a `compliance:exempt` label to your PR
2. The compliance check re-triggers automatically (via the `labeled` event)
3. The agent runs a **lightweight audit** instead of the full checklist

### What's checked in exempt mode

| Check | Full audit | Exempt audit |
|-------|-----------|--------------|
| Ticket traceability | Yes | **Skipped** |
| Issue/spec files | Yes | **Skipped** |
| Test coverage | Yes | **Skipped** |
| Scope validation | - | **Yes** (verifies change is genuinely trivial) |
| Security scan | Yes | Yes |
| Review tools | Yes | Yes |

### What qualifies as exempt

- CI/CD workflow changes (`.github/workflows/`)
- Dependency version pins
- Typo and formatting fixes
- Config file updates
- Documentation-only changes

### What does NOT qualify

The agent will **reject the exemption** (fail the check) if:
- The PR includes substantial new features or business logic
- Source code changes are too large or complex
- The change modifies security-sensitive code

This prevents abuse — you can't slap `compliance:exempt` on a feature PR to skip traceability.

### Setup

To enable exempt mode, make sure your caller workflow:

1. Includes `labeled` in the event types:
   ```yaml
   types: [opened, synchronize, reopened, ready_for_review, labeled]
   ```

2. Passes PR labels:
   ```yaml
   pr_labels: ${{ join(github.event.pull_request.labels.*.name, ',') }}
   ```

3. Create the label in your GitHub repo:
   ```bash
   gh label create "compliance:exempt" --description "Skip ticket traceability for trivial changes"
   ```

## Confidence Scoring

The agent assigns a confidence score (0–100%) based on its investigation:

| Range | Meaning |
|-------|---------|
| 90–100 | Full traceability. Tickets verified, specs aligned, tests exist, reviews clean. |
| 70–89 | Minor gaps. Config without dedicated tests, slightly stale spec. Audit trail is solid. |
| 50–69 | Significant gaps. Missing specs, several untested files, but tickets exist. |
| 30–49 | Major issues. Missing tickets for substantial code, no tests, unresolved critical findings. |
| 0–29 | No traceability. No tickets, no docs, no tests. |

The `confidence_threshold` input (default: 70) determines pass/fail.

## Expected File Structure

```
your-repo/
├── issues/
│   ├── PROJ-123.md      # Product requirements
│   └── PROJ-456.md
├── specs/
│   ├── feature-auth.md  # Technical specifications
│   └── proj-123.md
└── .github/
    └── workflows/
        └── compliance.yml
```

### Issue Files (issues/*.md)

Product requirements. Should contain:
- User stories and acceptance criteria
- Business logic requirements
- UX requirements

Naming: `{TICKET-ID}.md` (e.g., `PROJ-123.md`)

### Spec Files (specs/*.md)

Technical specifications. Should contain:
- Architecture decisions and trade-offs
- Implementation approach
- API contracts / data models
- Edge cases and error handling

## Security

This checker runs in a separate repository with restricted access:
- Developers cannot modify the compliance logic in the same PR
- Changes to this repo require separate review
- Audit trail of compliance rule changes

## Development

### Local Testing

```bash
export GEMINI_API_KEY=your-key
export LINEAR_API_KEY=your-key
export PR_BODY="Implements PROJ-123"
export PR_TITLE="PROJ-123: Add auth flow"
export PR_NUMBER=42
export REPO=your-org/your-repo
export TARGET_REPO=/path/to/repo
export TICKET_PATTERN="PROJ-[0-9]+"
export BASE_BRANCH=main
export REQUIRED_REVIEWERS="coderabbit"
export CONFIDENCE_THRESHOLD=70

python scripts/verify_compliance.py
```

### Requirements

- Python 3.12+
- `httpx` — HTTP client
- `google-genai` — Gemini API client

## License

MIT
