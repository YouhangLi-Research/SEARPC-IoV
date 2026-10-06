# Contributing

Bug reports and reproducibility questions are welcome. Please include the command, Python version, operating system, and complete error output.

For code changes:

1. Create an isolated Python 3.10–3.13 environment.
2. Install `requirements.txt`.
3. Keep generated outputs outside `artifact/`.
4. Run `python run.py check` before submitting a change.
5. Add or update tests when behavior changes.

Scientific parameters and frozen reference outputs must not be changed without a documented protocol revision and regenerated manifests.
