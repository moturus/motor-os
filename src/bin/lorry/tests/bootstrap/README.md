# Bootstrap validation fixtures

Everything in this directory is validation-only. It is not linked into Lorry,
called by normal Lorry commands, or used by the Motor OS packaging build.

`build_minimal_seed_image.py` and `minimal-seed-image.yaml` create the
disposable patched-source-only Motor image used by
`src/tests/lorry-motor-registry-cache.sh`. The fixture deliberately omits the
production crates.io seed so the test can prove that native Lorry populates a
fresh repository and rebuilds curl from it. Debug/release selection, VM
scripts, SSH readiness, and guest filesystem-layout assertions are properties
of that validation lane, not Lorry features.

Run its focused unit test from `src/bin/lorry` with:

```sh
python3 -m unittest discover -s tests/bootstrap -p 'test_*.py' -v
```
