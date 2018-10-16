#! /bin/bash -eu
#
#
# Clear:
#  release=XYZ http://linux-ftp.intel.com/pub/mirrors/clearlinux/releases/$release/clear/clear-$release-live.img.xz
#
progname=$(basename $0)
destdir=$1
image_file=$2
image_type=${3:-}
tmpdir=${TMPDIR:-`mktemp -d $progname-XXXXXX`}

trap cleanup EXIT

function help() {
    cat <<EOF
$progname DIRECTORY IMAGEFILE [IMAGETYPE]
EOF
}

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
        sudo umount $mounted_dir
    done
    if ! [ -z "$loop_dev" ]; then
        sudo losetup -d $loop_dev
    fi
    if [ "$tmpdir" != "${TMPDIR:-}" ]; then
        # we made it, we wipe it
        info removing tmpdir $tmpdir
        rm -rf $tmpdir
    fi
}

if echo $image_file | grep \.xz$; then
    info decompressing $image_file
    xz -kd $image_file
    image_file=${image_file%%.xz}
fi

boot_part=""
root_part=""
base=$(basename $image_file)
if [ -z "$image_type" ]; then
    case "$base" in
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
    fedora)
        root_part=p1
        ;;
    rootfswic)
        root_part=p2
        ;;
   
    *)
        error Unknown image type for $image_file
        help 1>&2
        exit 1
esac


loop_dev=$(sudo losetup --show -fP $image_file)
info loop device $loop_dev
lsblk $loop_dev

mkdir $tmpdir/root
sudo mount ${loop_dev}${root_part} $tmpdir/root
mounted_dirs="${mounted_dirs:-} $tmpdir/root"
info mounted ${loop_dev}${root_part} in $tmpdir/root

if ! [ -z "$boot_part" ]; then
    # clear does this
    sudo mount ${loop_dev}${boot_part} $tmpdir/root/boot
    mounted_dirs="$tmpdir/root/boot ${mounted_dirs:-}"
    info mounted ${loop_dev}${boot_part} in $tmpdir/root/boot
fi

# This assumes we have mounted the boot partition on root/boot, to get
# all the boot goodies
if ! [ -d $destdir ]; then
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
    fedora|clear)
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
        ;;
    clear)
        # Harcode: disable ANSI script sequences, as they make
        # scripting way harder
        sudo sed -i 's/^export PS1=.*/export PS1="\\u@\\H \\w $endchar "/' \
            $destdir/usr/share/defaults/etc/profile.d/50-prompt.sh 
        info $image_type: disable ANSI coloring in prompt, makes scripting harder
        ;;
    yocto)
        echo 'U0:12345:respawn:/bin/start_getty 115200 ttyUSB0 vt102' |
            sudo tee -a $destdir/etc/inittab
        info $image_type: added ttyUSB0 to automatic console spawn
        ;;
esac
