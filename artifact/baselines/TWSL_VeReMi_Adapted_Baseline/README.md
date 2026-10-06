# TWSL paper-aligned baseline

This directory contains an independent implementation of the Three-Weight Subjective Logic (TWSL) reputation method proposed by Kang et al. It is used as a stage-matched vehicle-trust baseline in the SEARPC evaluation.

Source paper: J. Kang et al., “Blockchain for Secure and Efficient Data Sharing in Vehicular Edge Computing and Networks,” *IEEE Internet of Things Journal*, vol. 6, no. 3, pp. 4660–4670, 2019. DOI: [10.1109/JIOT.2018.2875542](https://doi.org/10.1109/JIOT.2018.2875542).

## Implemented scope

- Equations (1)–(13) from the source paper.
- Interaction-frequency, event-recency, and trajectory-similarity weights.
- Speed, LCS-based position, and direction dissimilarities.
- Weighted recommendation aggregation and local/recommended opinion fusion.
- Single-snapshot, periodic-series, and precomputed-opinion entry points.
- Unit tests, input schemas, fixed configurations, and example data.

This is not an author-official implementation. It intentionally excludes SEARPC-specific role separation, certified-domain bounds, authorization states, RSU lifecycle control, and committee reconfiguration.

## Installation and tests

From this directory:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

The top-level command `python run.py check` also runs these tests with the complete artifact suite.

## Minimal example

```bash
python -m twsl_baseline run \
  --interactions examples/interactions.csv \
  --trajectories examples/trajectories.csv \
  --config configs/paper_table_ii.json \
  --out-dir example_output
```

Outputs include pairwise local opinions, final TWSL reputations, and a manifest containing the configuration and input hashes.

For a time series:

```bash
python -m twsl_baseline series \
  --interactions examples/interactions.csv \
  --trajectories examples/trajectories.csv \
  --config configs/paper_table_ii.json \
  --out-dir series_output
```

For a precomputed local-opinion stream:

```bash
python -m twsl_baseline fuse \
  --opinions examples/local_opinions.csv \
  --config configs/paper_table_ii.json \
  --out-dir fuse_output
```

## Configuration choice

The source paper's prose states that the positive-event weight `theta` is smaller than the negative-event weight `tau`, whereas its parameter table lists `theta=0.6` and `tau=0.4`. This package preserves both declared interpretations:

- `configs/paper_table_ii.json` uses the literal parameter table and is the default profile.
- `configs/text_constraint_consistent.json` uses `theta=0.4` and `tau=0.6` as a named sensitivity profile.

The evaluation profile is selected before testing and recorded in the output manifest.

## Input schema

`interactions.csv` requires:

| Column | Meaning |
| --- | --- |
| `timestamp` | Unix seconds or ISO-8601 time |
| `requestor_id` | vehicle forming the opinion |
| `provider_id` | vehicle being evaluated |
| `outcome` | verified positive/negative interaction outcome |
| `communication_quality` | successful-transmission probability in `[0,1]` |

`trajectories.csv` requires:

| Column | Meaning |
| --- | --- |
| `timestamp` | Unix seconds or ISO-8601 time |
| `vehicle_id` | vehicle identifier |
| `x`, `y` | position in one projected coordinate system |
| `speed` | speed in one consistent unit |
| `direction_radians` | optional heading; otherwise derived from the segment |

For continuous GPS coordinates, any nonzero LCS position tolerance is a dataset adaptation and is recorded explicitly. Geographic degrees must be projected before applying a metric tolerance.

## Files

```text
configs/                    fixed parameter profiles
examples/                   minimal executable inputs
schema/                     input-column definitions
src/twsl_baseline/          implementation and command-line interface
tests/                      equation and end-to-end tests
SEARPC_MAPPING_PROTOCOL.md   evaluation mapping and timing rules
PAPER_ALIGNMENT.md          equation map and declared implementation choices
IMPLEMENTATION_CHECKS.md        packaged validation record
```

The TWSL result is compared only at the role/source authorization layer. It is not extended with SEARPC's committee or finality mechanisms.
