# Bundled experiment inputs

The files in `derived/` are the exact frozen inputs consumed by the vehicle
authorization and source-domain experiments. They are derived research data,
not additional traffic datasets or raw road-deployment records.

| File | Contents | Consumers |
| --- | --- | --- |
| `rq2_trace_bundle_exact.npz` | Provider indices, attack labels, calibrated probabilities, uncertainties, attacker sets, and certified-domain indices | Role authorization, cold start, content-risk construction |
| `SEARPC_holdout_holdout_predictions.csv` | 582,100 ordered holdout prediction rows; two attack scenarios | Domain-control mechanisms and BRS/TWSL source baselines |

Both scenarios have 291,050 prediction rows. Sampling every eighth row produces
36,382 events per scenario; the NPZ records 1,165 indexed identities and 233
data-attacker identities per scenario. The two files are immutable inputs to
the public reproduction commands; their registered SHA-256 values are checked
before evaluation.

```bash
python run.py vehicle-inputs
```

The inputs originate from **VeReMi NextGen**, by Artur Hermann, Jan Niklas
Remmers, Dennis Eisermann, Benjamin Erb, and Frank Kargl, Institute of
Distributed Systems, Ulm University (2026), DOI
<https://doi.org/10.5281/zenodo.19665762>.

Copyright (C) 2026 Institute of Distributed Systems, Ulm University. The
source dataset is licensed under **Creative Commons Attribution 4.0
International**, <https://creativecommons.org/licenses/by/4.0/>. Its license
file is available at
<https://zenodo.org/records/19665762/files/LICENSE.txt?download=1>.

SEARPC modifications comprise feature-based calibrated predictions,
uncertainty estimates, stride-eight event selection, integer identity
reindexing, deterministic domain assignment, and array packaging. The
source attribution and CC BY 4.0 terms apply to these derived data; the
repository's MIT software license does not replace the dataset license.
The source and derived data are provided as-is, without warranties. Inclusion
does not imply endorsement by the dataset authors.

See `docs/DATA.md` for the official-data path, split accounting, and prediction
provenance. Raw archives and the official CaTCH implementation are obtained
separately from their original distributors.
