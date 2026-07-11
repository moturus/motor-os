#!/bin/sh

rm -f /tmp/firecracker.socket
rm -f /tmp/firecracker.log
touch /tmp/firecracker.log

WD="$(dirname $0)"
# Firecracker strictly requires absolute paths in its JSON configuration
ABS_WD="$(cd "$WD" && pwd)"

cat <<EOF > /tmp/fc-config.json
{
  "boot-source": {
    "kernel_image_path": "${ABS_WD}/kloader",
    "initrd_path": "${ABS_WD}/initrd",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=192.168.4.2:::255.255.255.0::eth0:off"
  },
  "drives": [
    {
      "drive_id": "disk0",
      "path_on_host": "${ABS_WD}/motor-os.img",
      "is_root_device": false,
      "is_read_only": false
    }
  ],
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "a4:a1:c2:00:00:01",
      "host_dev_name": "moto-tap"
    }
  ],
  "machine-config": {
    "vcpu_count": 4,
    "mem_size_mib": 1024
  },
  "logger": {
    "log_path": "/tmp/firecracker.log",
    "level": "Debug",
    "show_level": true,
    "show_log_origin": true
  }
}
EOF

firecracker --enable-pci --api-sock /tmp/firecracker.socket --config-file /tmp/fc-config.json

