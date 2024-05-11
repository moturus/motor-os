#!/bin/sh

../../../alioth/target/release/alioth \
    -l debug,alioth::acpi=warn \
    --log-to-file \
    run \
    --pvh kloader \
    --initramfs initrd \
    --mem-size 256M \
    --blk moturus.full.img \
    --num-cpu=4 \
    --net 'if=moto-tap,mac=a4:a1:c2:00:00:01,mtu=1500'
