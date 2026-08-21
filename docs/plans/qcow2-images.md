# QCOW2 Main and Developer Images

## Summary

Keep `motor-os-base.img` raw for Firecracker. Produce the standard and
developer images as `motor-os.qcow2` and `motor-os-dev.qcow2`, and update all
build, launch, test, and documentation consumers accordingly.

## Implementation

- Add an explicit raw/qcow2 format to imager configuration. Build qcow2 images
  by constructing the existing raw MBR disk in scratch space and converting it
  with `qemu-img convert -f raw -O qcow2`; publish output only after conversion
  succeeds. Raw image builds must not require `qemu-img`.
- Keep the `base.img`, `main.img`, and `dev.img` Make targets. Remove stale
  legacy main/dev raw artifacts when rebuilding, and make `qemu-utils` an
  explicit complete-build host dependency.
- Make QEMU and Cloud Hypervisor select raw or qcow2 explicitly from the image
  filename. Keep Firecracker raw-only, remove Firecracker from `run-dev.sh`,
  and remove the unverifiable Puff helper.
- Update every test, build check, and user-facing reference to the new artifact
  names.

## Interfaces

- `motor-os.img` becomes `motor-os.qcow2`.
- `motor-os-dev.img` becomes `motor-os-dev.qcow2`.
- `motor-os-base.img` remains raw and unchanged.
- `MOTO_IMAGE` continues to select an image; launchers accept `.img`/`.raw` as
  raw and `.qcow2` as qcow2, rejecting unsupported suffixes.
- `run-dev.sh --vmm fc` becomes an argument error.

## Tests

- Unit-test imager configuration, conversion success, and conversion failure.
- Add a host-only launcher test with fake VMM executables and include it in
  `src/tests/full-test.sh`.
- Run imager tests in debug and release, build all three image targets, verify
  formats with `qemu-img info`, and run the available debug/release VM suites.
- Smoke-test base with Firecracker and main with Cloud Hypervisor where the
  host supports those VMMs.

## Assumptions

- Use ordinary sparse qcow2 output with no compression or backing files.
- This is non-core work, so the repeated three-run core OS test requirement
  does not apply.
- Keep implementation commits to approximately 100–300 changed lines.
