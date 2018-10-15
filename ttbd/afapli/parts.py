#! /usr/bin/python

import logging
import os
import subprocess

# Snipped lifted from https://stackoverflow.com/a/29156997
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno = True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_char_p)

def mount(source, target, fs, options=''):
    ret = libc.mount(source, target, fs, 0, options)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno,
                      "Error mounting {} ({}) on {} with options '{}': {}".
                      format(source, fs, target, options, os.strerror(errno)))
# End of snippet lifted from https://stackoverflow.com/a/29156997
def umount(source):
    ret = libc.umount(source)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "Error umounting {}: {}".
                      format(source, os.strerror(errno)))


# creates from scratch

# Seriously, pyparted is quite low-level, hard to understand, so we'll
# stick to do it using cmdline parted.

if True:
    # physical vs
    boot_size = 2
    swap_size = 10
    home_size = 50
    root_size = 15
else:
    # virtual
    boot_size = 1
    swap_size = 2
    home_size = 2
    root_size = 2

def disk_partition(blkdev):
    log = logging.getLogger(blkdev)
    mntdir = "/mnt"

    devname = os.path.basename(blkdev)
    blocks = int(open("/sys/block/%s/size" % devname).read())
    block_size = int(open("/sys/block/%s/queue/physical_block_size"
                          % devname).read())
    size_gb = blocks * block_size / 1024 / 1024 / 1024

    cmdline = [
        "parted",
        "-a", "optimal",	# Decide optimal alignment
        # treat this as a script
        "-ms",
        blkdev,
        "unit", "GiB",
        "mklabel", "gpt",
        "mkpart", "primary", "fat32", "0%", str(boot_size),
        "name", "1", "tcf-boot",
        "set", "1", "boot", "on",	# so we boot from this
        "mkpart", "primary", "linux-swap", str(boot_size), str(boot_size + swap_size),
        "name", "2", "tcf-swap",
        "mkpart", "primary", "ext4", str(boot_size + swap_size), str(boot_size + swap_size + home_size),
        "name", "3",  "tcf-home",
    ]
    pid = 4
    offset = boot_size + swap_size + home_size
    while offset + root_size < size_gb:
        cmdline += [
            "mkpart", "primary", "ext4", str(offset), str(offset + root_size),
            "name", str(pid), "tcf-root-%d" % pid,
        ]
        pid += 1
        offset += root_size

    log.info("repartitioning")
    subprocess.call(cmdline, shell = False)
    log.info("probing new partitions")
    subprocess.call([ "partprobe", blkdev ])

    # Don't rely in partition labels, they fail a lot
    boot_dev = blkdev + "1"

    log.info("creating boot FS %s", boot_dev)
    subprocess.call([ "mkfs.vfat", "-F32", "-n", "TCF-BOOT", boot_dev ])
    subprocess.call([ "sync" ])
    # We don't do anything with it -- the deployment script is the one
    # that will set it up accordingly for each image and install a
    # boot loader, etc.
    disk_reinit_swap_home(blkdev)

def disk_reinit_swap_home(blkdev):
    swap_dev = blkdev + "2"
    home_dev = blkdev + "3"
    # always reflash a couple things
    subprocess.call([ "mkswap", "-L", "tcf-swap", swap_dev ])

    subprocess.call([ "mkfs.ext4", "-FqL", "tcf-home", home_dev ])

logging.basicConfig(level = logging.INFO)
device = os.environ.get("DEVICE", "/dev/nbd0")
disk_partition(device)
