# Dogfood Report Template

Use this template when running SafeHarborCLI against a real protocol or fixture.

## Repo / Protocol

- Protocol:
- Repository:
- Commit:
- Foundry config:
- SafeHarbor config:
- Operator:
- Date:

## Commands Run

```sh
shcli scan --config safeharbor.toml
shcli review --config safeharbor.toml --approve-defaults
shcli compile --config safeharbor.toml
shcli battlechain prepare --config safeharbor.toml
shcli status --config safeharbor.toml
shcli doctor --config safeharbor.toml
shcli registry publish --config safeharbor.toml --manifest-uri ipfs://...
```

## What Worked

- Scan:
- Review:
- Compile:
- BattleChain prepare/status/doctor:
- Registry publish prepare/verify:
- Agent SDK consumption:

## Review Friction

- Candidate decisions that were unclear:
- Missing review context:
- Awkward default decisions:

## Schema Friction

- Missing fields:
- Awkward mappings:
- Fields that were too broad or too narrow:

## Default / Template Quality

- Useful structural candidates:
- Useful semantic templates:
- False positives:
- False negatives:

## Suggested Fixes

- CLI:
- docs:
- schema:
- recognizers:
- review UX:
