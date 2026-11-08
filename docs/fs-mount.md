# Mounting a data filesystem

These steps add a new 10 GiB Motor FS disk to a copy of the standard release
image, mount it at `/user/data`, and boot the result in Cloud Hypervisor. The
[imager command reference](imager.md) describes the commands used here, and
[filesystem permissions](fs-permissions.md) describes the mount configuration.

**0. Build the release images.** This also installs the `imager` that the
steps below use, in `vm_images/release/tools/`:

```sh
make -j$(nproc) BUILD=release
```

**1. Go to the release images directory.** The launchers accept disk files
only from their own directory.

```sh
cd vm_images/release
```

**2. Create the data disk.** This makes a sparse qcow2 file holding one empty
Motor FS with no partition table. Its root is `rwxrwxr-x`, so console and SSH
users can write to it.

```sh
tools/imager mkfs --size 10G data.qcow2
```

**3. Copy the standard image.** The original stays untouched.

```sh
cp motor-os.qcow2 my-os.qcow2
```

**4. Create the mount target.** A mount needs an existing directory.

```sh
tools/imager mkdir my-os.qcow2 /user/data
```

**5. Write the mount configuration.** Start from the shipped file, which
mounts the three memfs `tmp` directories, and add the new disk. The root
disk is device 0, so the first extra disk is `device = 1`. There is no
`partition` line because `mkfs` makes a disk with no partition table.

```sh
cp ../../img_files/motor-os-base/system/cfg/sys-fs.toml .
printf '\n[[mount]]\npath = "/user/data"\ntype = "motor-fs"\ndevice = 1\n' >> sys-fs.toml
```

**6. Install the configuration into the image.** It is System-only, so it has
to be changed offline:

```sh
tools/imager put my-os.qcow2 sys-fs.toml /system/cfg/sys-fs.toml
```

**7. Boot in Cloud Hypervisor with the data disk attached.** The `moto-tap`
interface must exist; run `./create-tap.sh` after a host reboot. With the
launcher:

```sh
MOTO_IMAGE=my-os.qcow2 ./run-chv.sh --extra-disk data.qcow2
```

The same VM started directly:

```sh
cloud-hypervisor-static --cpus boot=4 --memory size=1024M,thp=on \
  --console off --serial tty \
  --log-file /tmp/cloud-hypervisor.log -v \
  --kernel kloader --initramfs initrd \
  --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,ip=192.168.4.2,mask=255.255.255.0" \
  --disk path=my-os.qcow2,image_type=qcow2 path=data.qcow2,image_type=qcow2,readonly=off
```

The launcher does a few things the direct command does not:

- it uses `size=1024M,hugepages=on,prefault=on` when the host's hugetlbfs
  pool has enough free pages;
- it opens an API socket at `/tmp/chv` for `ch-remote`;
- it refuses to start while another Motor OS VM is running. Both would use
  `moto-tap` and the same guest address, so run only one at a time.

`--log-file … -v` can be dropped if the Cloud Hypervisor log is not needed.

**8. Check the mount in the guest.**

```
findmnt
```

The list includes the new filesystem:

```
4 /user/data virtio1 motor-fs rw ... 10737418240 -
```

Files written there, for example with `echo hi > /user/data/hello.txt`,
are still there after the VM is booted again with the same disk.

## Variations

- `mkfs --size 512M` or any other size; `--mode MODE` sets a different root
  mode.
- Add `read_only = true` to the `[[mount]]` entry for a read-only mount, and
  attach the disk with `--extra-disk-ro data.qcow2` (or `readonly=on`) so the
  VMM enforces it too.
- Files can be placed on the data disk before boot with
  `tools/imager put data.qcow2 HOST_FILE /PATH`.
- A disk with an MBR partition table needs `partition = N` in the entry.
