# Building Motor OS

Motor OS is built (cross-compiled) on Linux. The script below
has been tested on Ubuntu 24.04 and 26.04.

```sh
mkdir motor-dev
cd motor-dev
git clone https://github.com/moturus/motor-os.git
cd motor-os
src/build-motor-os.sh
```

The script above will install required Ubuntu packages (sudo will be required),
git clone and build llvm and Rust toolchains, and then build Motor OS
system and user programs, and the VM image.

It will also create moto-tap ipvtap interface (sudo will be required).

The build script above will NOT add routing from Motor OS VMs to the
internet, so `ping google.com` from inside the VM will fail. To enable
routing, run `sudo vm_images/release/nft-nat.sh`.

## Run Motor OS

If all of the above completed successfully, you can now do

```sh
sudo apt install qemu-system
sudo chmod a+rw /dev/kvm
cd $MOTORH/motor-os/vm_images/release
./run-qemu.sh
```

to run Motor OS in qemu.

While Motor OS is running, you can ssh into it using
`ssh-into-motor-os-vm.sh` script, or via

```sh
ssh -p 2222 -o IdentitiesOnly=yes -i test.key motor@192.168.4.2
```
