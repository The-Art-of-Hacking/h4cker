# Lychee Pre-commit Hooks

This repository provides three pre-commit hook options for lychee link checking:

## Quick Start

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/lycheeverse/lychee
    rev: lychee-v0.20.1  # Use latest lychee-v* tag
    hooks:
      - id: lychee  # Auto-installs lychee
```

## Hook Options

### 1. `lychee` (Recommended)

- **Auto-installs** lychee using cargo-binstall (fast) or cargo install (fallback)
- **Best user experience** - no manual setup required
- **Fast** - uses pre-built binaries when available

```yaml
- id: lychee
  args: ["--no-progress", "--exclude", "file://"]
```

### 2. `lychee-system` 

- **Requires manual installation**: `cargo install lychee`
- **Fastest** - no installation overhead
- **For users who already have lychee installed**

```yaml
- id: lychee-system
  args: ["--no-progress", "--exclude", "file://"]
```

### 3. `lychee-docker`

- **Auto-installs** via Docker image
- **Slower** - pulls Docker image
- **For environments where cargo is not available**

```yaml
- id: lychee-docker
  args: ["--no-progress", "--exclude", "file://"]
```

## Version Format

⚠️ **Important**: Use `lychee-v*` format for tags (e.g., `lychee-v0.20.1`), not `v*` format.

The tag format changed after v0.15.1 to support cargo-binstall URL patterns:
- ❌ `rev: v0.20.1` (doesn't exist)  
- ✅ `rev: lychee-v0.20.1` (correct format)

## Common Configuration

```yaml
repos:
  - repo: https://github.com/lycheeverse/lychee
    rev: lychee-v0.20.1
    hooks:
      - id: lychee
        args: 
          - --no-progress
          - --exclude=file://
          - --exclude=mailto:
```

## Troubleshooting

**"Executable `lychee` not found"**: Use the default `lychee` hook (not `lychee-system`) for auto-installation.

**Tag format issues**: Ensure you're using `lychee-v*` format, not `v*` format for versions after 0.15.1.