# Third-party attribution and licenses

## VeReMi NextGen data

Source: Artur Hermann, Jan Niklas Remmers, Dennis Eisermann, Benjamin Erb,
and Frank Kargl (2026), *VeReMi NextGen: A Dataset for Evaluating Misbehavior
Detection Systems in VANETs*, IEEE Vehicular Networking Conference.

Dataset: <https://doi.org/10.5281/zenodo.19665762>.
Copyright (C) 2026 Institute of Distributed Systems, Ulm University.
Source dataset license: Creative Commons Attribution 4.0 International,
<https://creativecommons.org/licenses/by/4.0/>.
Original license text:
<https://zenodo.org/records/19665762/files/LICENSE.txt?download=1>.

The files under `data/derived/` and the receiver predictions under
`figures/experimental/fig5_to_fig11/data/` are SEARPC-derived research
inputs. Their changes are described in `data/README.md`. Source attribution,
CC BY 4.0 conditions, and the original disclaimer of warranties are retained.
The MIT code license does not relicense the source dataset. There is no
implied endorsement by its authors. Raw archives are not included.

## Published-method adapters

BRS, TWSL, Yadav, and BRBC implementations in this artifact are independent,
stage-matched implementations/adaptations, not official author releases.
See `docs/BASELINES.md`, the associated protocol records, and the TWSL package's
paper-alignment documentation for citations and implemented scope.

The CaTCH adapter loads separately obtained official VeReMi NextGen source,
pinned to the recorded commit and source-file hashes. The official repository
is <https://github.com/VeReMi-dataset/VeReMi-NextGen>; its source license and
third-party notices remain applicable. That official source is not included.

## Python dependencies

NumPy, SciPy, scikit-learn, Matplotlib, pandas, cryptography, and Pillow are
installed separately through `requirements.txt`. Their respective licenses
and notices remain applicable; dependency source and binary distributions
are not bundled in this artifact.
