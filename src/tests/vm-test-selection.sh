# Resolve a test phase to one build profile, image target, image file, and VMM
# runner. This file is sourced by test harnesses; it does not launch or build.
select_test_vm() {
  if [ "$#" -ne 4 ]; then
    echo "select_test_vm: expected ROOT BUILD PHASE VMM" >&2
    return 2
  fi

  local root="$1" build="$2" phase="$3" vmm="$4"
  local label target image

  case "$build" in
    debug | release) ;;
    *)
      echo "select_test_vm: unsupported build profile '$build'" >&2
      return 2
      ;;
  esac
  case "$vmm" in
    qemu) label=QEMU ;;
    chv) label="Cloud Hypervisor" ;;
    fc) label=Firecracker ;;
    *)
      echo "select_test_vm: unsupported VMM '$vmm'" >&2
      return 2
      ;;
  esac

  case "$phase:$vmm" in
    standard:qemu | standard:chv | boot-check:qemu | boot-check:chv)
      target=main.img
      image=motor-os.qcow2
      ;;
    standard:fc)
      target=raw.img
      image=motor-os.img
      ;;
    boot-check:fc)
      target=base.img
      image=motor-os-base.img
      ;;
    system-console:qemu | system-console:chv | system-console:fc)
      target=system-tty.img
      image=motor-os-system-tty.img
      ;;
    developer:qemu | developer:chv)
      target=dev.img
      image=motor-os-dev.qcow2
      ;;
    developer:fc)
      echo "select_test_vm: Firecracker does not support developer images" >&2
      return 2
      ;;
    *)
      echo "select_test_vm: unsupported test phase '$phase'" >&2
      return 2
      ;;
  esac

  TEST_VM_LABEL="$label"
  TEST_VM_IMG_TARGET="$target"
  TEST_VM_IMAGE="$image"
  TEST_VM_PROFILE="$build"
  TEST_VM_IMG_DIR="$root/vm_images/$build"
  TEST_VM_RUNNER="$TEST_VM_IMG_DIR/run-$vmm.sh"
}
