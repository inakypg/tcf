#! /bin/bash -eu
#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0


function help() {
    cat <<EOF
$progname DIRECTORY IMAGEFILE [IMAGETYPE]

Clearlinux:

  $ wget https://download.clearlinux.org/releases/25930/clear/clear-25930-live.img.xz
  $ $progname clear:live:25930::x86_64 clear-25930-live.img.xz

Yocto:

  $ wget http://downloads.yoctoproject.org/releases/yocto/yocto-2.5.1/machines/genericx86-64/core-image-minimal-genericx86-64.wic
  $ $progname yocto:core-image-minimal:2.5.1::x86_64 core-image-minimal-genericx86-64.wic

Fedora:

  $ https://mirrors.rit.edu/fedora/fedora/linux/releases/29/Workstation/x86_64/iso/Fedora-Workstation-Live-x86_64-29-1.2.iso
  $ $progname fedora:live:29::x86_64 Fedora-Workstation-Live-x86_64-29-1.2.iso

Ubuntu:

  $ wget http://releases.ubuntu.com/18.10/ubuntu-18.10-desktop-amd64.iso
  $ $progname ubuntu:live:18.10::x86_64 ubuntu-18.10-desktop-amd64.iso

Using QEMU

1. create a 20G virtual disk:

     $ qemu-img create -f qcow2 ubuntu-18.10.qcow2 20G
     $ qemu-img create -f qcow2 Fedora-Workstation-29.qcow2 20G

2. Install using QEMU all with default options (click next). Power
   off the machine when done instead of power cycling

     $ qemu-system-x86_64 --enable-kvm -m 2048 -hdah ubuntu-18.10.qcow2 -cdrom ubuntu-18.10-desktop-amd64.iso
     $ qemu-system-x86_64 --enable-kvm -m 2048 -hda Fedora-Workstation-29.qcow2 -cdrom Fedora-Workstation-Live-x86_64-29-1.2.iso

   Key thing here is to make sure everything is contained in a
   single partition (first partition).

   For Ubuntu 18.10:
     - select install
     - select any language and keyboard layout
     - Normal installation
     - Erase disk and install Ubuntu
     - Create a user 'Test User', with any password
     - when asked to restart, restart, but close QEMU before it
       actually starts again

   For Fedora 29:
     - turn off networking
     - select install to hard drive
     - select english keyboard
     - select installation destination, "CUSTOM" storage configuration
       > DONE
     - Select Standard partition
     - Click on + to add a partition, mount it on /, 20G in size
       (the system later will add boot and swap, we only want what goes
       in the root partition).
       Select DONE
     - Click BEGIN INSTALLATION
     - Click QUIT when done
     - Power off the VM

3. Create image:

     $ $progname ubuntu:desktop:18.10::x86_64 ubuntu-18.10.qcow2

EOF
}

progname=$(basename $0)

if [ $# -lt 2 -o $# -gt 3 ]; then
    help 1>&2
    exit 1
fi

destdir=$1
image_file=$2
image_type=${3:-}
tmpdir=${TMPDIR:-`mktemp -d $progname-XXXXXX`}

trap cleanup EXIT

function info() {
    echo I: "$@" 1>&2
}

function warning() {
    echo W: "$@" 1>&2
}

function error() {
    echo E: "$@" 1>&2
    exit 1
}

loop_dev=""
mounted_dirs=""
function cleanup() {
    for mounted_dir in $mounted_dirs; do
        info unmounting $mounted_dir
        sudo umount -l $mounted_dir
    done
    if ! [ -z "$loop_dev" ]; then
        sudo losetup -d $loop_dev
    fi
    if ! [ -z "${qemu_nbd_pid:-}" ]; then
        sudo kill $qemu_nbd_pid
        sleep 1s
        sudo kill -9 $qemu_nbd_pid 2> /dev/null || :
    fi
    if [ "$tmpdir" != "${TMPDIR:-}" ]; then
        # we made it, we wipe it
        info removing tmpdir $tmpdir
        rm -rf $tmpdir
    fi
}

if echo $image_file | grep -q \.xz$; then
    info decompressing $image_file
    xz -kd $image_file
    image_file=${image_file%%.xz}
fi

boot_part=""
root_part=""
base=$(basename $image_file)
if [ -z "$image_type" ]; then
    case "$base" in
        android-*.iso)
            image_type=android
            ;;
        *qcow2)
            image_type=qcow2
            nbd_dev=/dev/nbd0
            ;;
        tcf-live.iso)
            image_type=tcflive;;
        Fedora-Workstation-Live-*.iso)
            image_type=fedoralive;;
        ubuntu-*.iso)
            # assuming these are common
            image_type=debian;;
        # clear, yocto core image minimal
        clear*)
            image_type=clear;;
        core*wic)
            image_type=yocto;;
        Fedora-*)
            image_type=fedora;;
        *rootfs.wic)
            image_type=rootfswic;;

        *)
            error Unknown image type for $image_file
            help 1>&2
            exit 1
    esac
fi

case "$image_type" in
    # clear, yocto core image minimal
    clear)
        boot_part=p1
        root_part=p2
        ;;
    yocto)
        boot_part=p1
        root_part=p2
        ;;
    debian|fedoralive|tcflive)
        root_part=p1
        ;;
    rootfswic)
        boot_part=p1
        root_part=p2
        ;;
    android|qcow2)
        ;;
    *)
        error Unknown image type for $image_file
        help 1>&2
        exit 1
esac

if [ $image_type = qcow2 ]; then
    sudo modprobe nbd
    sudo qemu-nbd -c $nbd_dev -P 1 -r $image_file &
    qemu_nbd_pid=$!
    info QEMU NBD at $qemu_nbd_pid
else
    loop_dev=$(sudo losetup --show -fP $image_file)
    info loop device $loop_dev
    lsblk $loop_dev
fi

mkdir $tmpdir/root
set -e
if [ $image_type = debian ]; then
    mkdir -p $tmpdir/iso $tmpdir/root
    sudo mount -o loop ${loop_dev}p1 $tmpdir/iso
    mounted_dirs="$tmpdir/iso ${mounted_dirs:-}"
    info mounted ${loop_dev}${root_part} in $tmpdir/iso

    squashfs_file=$(find $tmpdir/iso -iname filesystem.squashfs)
    sudo mount -o loop $squashfs_file $tmpdir/root
    info mounted $squashfs_file in $tmpdir/root

elif [ $image_type = android ]; then

    mkdir -p $tmpdir/iso
    sudo mount -o loop ${loop_dev} $tmpdir/iso
    mounted_dirs="$tmpdir/iso ${mounted_dirs:-}"
    info mounted ${loop_dev} in $tmpdir/iso

elif [ $image_type == fedoralive -o $image_type == tcflive ]; then

    mkdir -p $tmpdir/iso $tmpdir/squashfs
    sudo mount -o loop ${loop_dev}p1 $tmpdir/iso
    mounted_dirs="$tmpdir/iso ${mounted_dirs:-}"
    info mounted ${loop_dev}${root_part} in $tmpdir/iso

    sudo mount -o loop $tmpdir/iso/LiveOS/squashfs.img $tmpdir/squashfs
    mounted_dirs="$tmpdir/squashfs ${mounted_dirs:-}"
    info mounted $tmpdir/iso/LiveOS/squashfs.img in $tmpdir/squashfs

    if [ $image_type == fedoralive ]; then
        sudo mount -r -o loop $tmpdir/squashfs/LiveOS/rootfs.img $tmpdir/root
        info mounted $tmpdir/squashfs/LiveOS/rootfs.img in $tmpdir/root
    elif [ $image_type == tcflive ]; then
        # norecovery: if the ext3 fs has a dirty log, we don't want to do it now
        sudo mount -o norecovery,loop $tmpdir/squashfs/LiveOS/ext3fs.img $tmpdir/root
        info mounted $tmpdir/squashfs/LiveOS/ext3fs.img in $tmpdir/root
    else
        error BUG! Unknown image type for $image_type
    fi
    mounted_dirs="$tmpdir/root ${mounted_dirs:-}"
elif [ $image_type == qcow2 ]; then

    sudo mount -r -o noload ${nbd_dev} $tmpdir/root
    info mounted ${nbd_dev} in $tmpdir/root
    mounted_dirs="$tmpdir/root ${mounted_dirs:-}"

else

    sudo mount ${loop_dev}${root_part} $tmpdir/root
    info mounted ${loop_dev}${root_part} in $tmpdir/root
    mounted_dirs="$tmpdir/root ${mounted_dirs:-}"

fi

if ! [ -z "$boot_part" ]; then
    # clear does this
    sudo mount ${loop_dev}${boot_part} $tmpdir/root/boot
    mounted_dirs="$tmpdir/root/boot ${mounted_dirs:-}"
    info mounted ${loop_dev}${boot_part} in $tmpdir/root/boot
fi

# This assumes we have mounted the boot partition on root/boot, to get
# all the boot goodies
if [ $image_type == android ]; then

    mkdir -p $destdir/android/data $destdir/boot/loader/entries
    cp \
        $tmpdir/iso/initrd.img \
        $tmpdir/iso/kernel \
        $tmpdir/iso/ramdisk.img \
        $tmpdir/iso/system.sfs \
        $destdir/android/
    chmod 0644 $destdir/android/*
    chmod ug=rwx,o=x $destdir/android/data
    sudo chown root:root $destdir/android -R
    info android: made squashfs based root filesystem

    # Now, here we cheat a wee bit -- we make this look like a
    # traditional Linux boot environment so the code in
    # tcfl.pos.boot_config can pick it up and make it work with no changes
    (
        cd $destdir/boot
        sudo ln ../android/kernel kernel
        sudo ln ../android/initrd.img initrd.img
    )

    # Make this fake boot entries so the POS code can decide what to
    # boot and how
    cat > $destdir/boot/loader/entries/android.conf <<EOF
title Android
linux /kernel
initrd /initrd.img
options quiet root=/dev/ram0 androidboot.selinux=permissive vmalloc=192M buildvariant=userdebug SRC=/android
EOF
    info android: faked Linux-like /boot environment

elif ! [ -d $destdir ]; then

    mkdir $destdir
    info created $destdir, transferring
    sudo tar c --selinux --acls --xattrs -C $tmpdir/root . \
        | sudo tar x --selinux --acls --xattrs -C $destdir/.
    info $destdir: diffing verification
    sudo diff  --no-dereference -qrN $tmpdir/root/. $destdir/.
    info $destdir: setting up

else

    warning assuming image already in $destdir, setting up

fi

if [ $image_type = debian ]; then

    dir=$(dirname $squashfs_file)
    kversion=$(file $dir/vmlinuz | sed  -e 's/^.* version //' -e 's/ .*//')
    cp $dir/initrd $destdir/initramfs-$version
    cp $dir/vmlinuz $destdir/vmlinuz-$version
fi

# Remove the root password and unset the counters so you are not
# forced to change it -- we want passwordless login on the serial
# console or anywhere we access the test system.

for shadow_file in \
    $destdir/usr/share/defaults/etc/shadow \
    $destdir/etc/shadow; do
    if sudo test -r $shadow_file; then
        sudo sed -i 's/root:.*$/root::::::::/' $shadow_file
        info $shadow_file: removed root password and reset counters
    fi
done

case $image_type in
    fedora*|clear)
        # Harcode enable getty on ttyUSB0 (FIXME: maybe do in the
        # setup script?) -- it doesn't autostart it from /proc/cmdline
        # because by the time we boot, ttyUSB0 hasb't been detected
        # yet
        # ALSO, force 115200 is the only BPS we support
        sudo sed -i \
             's|^ExecStart=-/sbin/agetty -o.*|ExecStart=-/sbin/agetty 115200 %I $TERM|' \
             $destdir/usr/lib/systemd/system/serial-getty@.service
        info $image_type: force settings of ttyUSB0 console
        sudo chroot $destdir systemctl enable serial-getty@ttyUSB0
        info $image_type: force enabling ttyUSB0 console
        if [ $image_type == clear ]; then
            # Harcode: disable ANSI script sequences, as they make
            # scripting way harder
            sudo sed -i 's/^export PS1=.*/export PS1="\\u@\\H \\w $endchar "/' \
                 $destdir/usr/share/defaults/etc/profile.d/50-prompt.sh
            info $image_type: disable ANSI coloring in prompt, makes scripting harder
        fi
        ;;
    yocto)
        echo 'U0:12345:respawn:/bin/start_getty 115200 ttyUSB0 vt102' |
            sudo tee -a $destdir/etc/inittab
        info $image_type: added ttyUSB0 to automatic console spawn
        ;;
esac

case $image_type in
    fedora*)
        # Disable SELinux -- can't figure out how to allow it to work
        # properly in allowing ttyUSB0 access to agetty so we can have
        # a serial console.
        sudo sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
        info $image_type: disabled SELinux
        ;;
    *)
        ;;
esac

case $image_type in
    fedoralive|qcow2)
        if [ -r "$destdir/etc/gdm/custom.conf" ]; then
            # Remove the GDM initial config user, so we don't get stuck
            # trying to configure the system
            sudo tee $destdir/etc/gdm/custom.conf <<EOF
[daemon]
InitialSetupEnable=false
EOF
            info $image_type: disabled GNOME initial setup
        fi
        ;;
    *)
        ;;
esac
