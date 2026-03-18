# Changesets

This project uses [changesets](https://github.com/changesets/changesets) for version management.

## Adding a changeset

When you make a change that should be released, run:

```bash
npx changeset
```

Follow the prompts to select which packages changed and the type of change (major, minor, patch).

## Releasing

Merging to `main` triggers the release workflow which either:
1. Creates a "Version Packages" PR that bumps versions and updates changelogs
2. Publishes to npm when the Version Packages PR is merged
