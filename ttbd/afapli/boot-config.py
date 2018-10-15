#! /usr/bin/python2

import distutils.version
import glob
import subprocess
import os
import re
import shutil
import sys


if len(sys.argv) < 5:
    sys.stderr.write("Missing arguments: DOMAIN DEVICE ROOTPART BOOTSRCDIR BOOTDSTDIR\n")
    sys.exit(1)
domain = sys.argv[1]
dev = sys.argv[2]
root_dev = sys.argv[3]
boot_srcdir = sys.argv[4]
boot_dstdir = sys.argv[5]

def makedirs_p(dirname, *args):
    try:
        os.makedirs(dirname, *args)
    except OSError:
        if not os.path.isdir(dirname):
            raise

def boot_extract_from_dir(output):
    """
    Given a list of files (normally) in /boot, decide which ones are
    Linux kernels and initramfs; select the latest version
    """
    kernel_regex = re.compile("(initramfs|initrd|bzImage|vmlinuz)-(.*)")
    kernel_versions = {}
    initramfs_versions = {}
    for line in output.splitlines():
        m = kernel_regex.match(line)
        if not m:
            continue
        file_name = m.groups()[0]
        kver = m.groups()[1]
        if "rescue" in kver or "kdump" in kver:
            # these are usually found on Fedora
            continue
        elif file_name in ( "initramfs", "initrd" ):
            if kver.endswith(".img"):
                # remove .img extension that has been pegged to the version
                kver = os.path.splitext(kver)[0]
            initramfs_versions[kver] = line
        else:
            kernel_versions[kver] = line

    if len(kernel_versions) == 1:
        kver = kernel_versions.keys()[0]
        return kernel_versions[kver], \
            initramfs_versions.get(kver, None), \
            ""
    elif len(kernel_versions) > 1:
        sys.stderr.write("ERROR: more than one kernel entry in %s\n"
                         % boot_srcdir)
        sys.exit(1)        
    else:
        return None, None, ""

def boot_extract_from_lec(lec_name):
    kernel = None
    initrd = None
    options = None
    # open a loader entry, extract the kernel, initramfs and options
    dibs_regex = re.compile("^\s*(?P<command>linux|initrd|efi|options)\s+"
                            "(?P<value>[^\n]+)\n?")
    with open(lec_name) as f:
        for line in f:
            m = dibs_regex.match(line)
            if not m:
                continue
            d = m.groupdict()
            command = d['command']
            value = d['value']
            if command == 'linux':
                kernel = value
            elif command == 'efi':
                kernel = value
            elif command == 'initrd':
                initrd == value
            elif command == 'options':
                options = value
            
    return kernel, initrd, options

# boot setup
les = glob.glob(os.path.join(boot_srcdir, "loader", "entries", "*.conf"))

options = ""
if len(les) > 1:
    sys.stderr.write("ERROR: more than one loader entry in %s\n" % boot_srcdir)
    sys.exit(1)
if len(les) == 1:
    kernel, initramfs, options = boot_extract_from_lec(les[0])
else:
    output = subprocess.check_output([ "ls", "-1", boot_srcdir ])
    kernel, initramfs, options = boot_extract_from_dir(output)

print "DEBUG", kernel
print "DEBUG", initramfs
print "DEBUG", options

# remove absolutization (some specs have it), as we need to copy from
# mounted filesystems
if os.path.isabs(kernel):
    kernel = kernel[1:]
if initramfs and os.path.isabs(initramfs):
    initramfs = initramfs[1:]


# /boot is always /dev/XSAD1 (first partition), we partition like that
boot_dev = dev + "1"

kws = dict(
    domain = domain,
    root_dev = root_dev,
    boot_dev = boot_dev,
    kernel = os.path.basename(kernel),
)
if initramfs:
    kws['initramfs'] = os.path.basename(initramfs)

# FIXME: bring from command line?
prefix_options = [
    "console=ttyUSB0,115200n81"
]

replace_options = {
    "root": "%(root_dev)s"
}

for option in prefix_options:
    if not option in options:
        options = option + " " + options

for option, value in replace_options.iteritems():
    if re.search(r"\n" + option, options):
        options = re.sub(r"\b" + option + "=\S+",
                         option + "=" + replace_options[option] % kws,
                         options)
    else:
        options += " " + option + "=" + value % kws
        
kws['options'] = options

le_dir = os.path.join(boot_dstdir, "loader", "entries")
# mkfs.vfat /boot, mount it
mounted = False
try:
    if root_dev != "nil":
        subprocess.call([ "mkfs.vfat", "-F32", "-n", "TCF-BOOT", boot_dev ])
        subprocess.call([ "sync" ])
        subprocess.call([ "mount", boot_dev, boot_dstdir ])
        mounted = True
        os.makedirs(le_dir)
        with open(os.path.join(boot_dstdir, "README"), "w") as readmef:
                  readmef.write("""\
    This boot configuration was written by TCF's AFAPLI client hack; it is
    meant to boot multiple Linux distros coexsiting in the
    same drive.

    Uses systemd-boot/gumniboot; partition one is /boot (EFI System
    Partition), where this file is located. Partition 2 is dedicated to
    swap. Partition 3 is dedicated to /home, which can be wiped and reset
    everytime a new test is run.

    Partitions 4-on are different root filesystems which can be reused by
    the system as needed for booting different domains (aka: distros
    configured in particular ways).
    """)

    le_c = os.path.join(le_dir, "domain-%(domain)s.conf" % kws)
    with open(le_c, "w") as le_f:
        shutil.copyfile(os.path.join(boot_srcdir, kernel),
                        os.path.join(boot_dstdir, os.path.basename(kernel)))
        le_f.write("""\
title %(domain)s
linux /%(kernel)s
    """ % kws)
        if 'initramfs' in kws:
            shutil.copyfile(os.path.join(boot_srcdir, initramfs),
                            os.path.join(boot_dstdir, os.path.basename(initramfs)))
            le_f.write("initrd /%(initramfs)s\n" % kws)
        le_f.write("options %(options)s\n" % kws)

    # Cleanup previous install, setup new one
    try:
        output = subprocess.check_output([ "bootctl", "remove" ])
    except subprocess.CalledProcessError as e:
        print "DEBUG bootctrl (failed) remove output: ", e.output
    try:
        output = subprocess.check_output([ "bootctl", "install" ])
    except subprocess.CalledProcessError as e:
        print "DEBUG bootctrl (failed) remove output: ", e.output
        raise
    # Now make sure the new entry is after IPv4, as we use IPv4's boot
    # to redirect to the right one
    #
    # $ efibootmgr
    # BootCurrent: 0006
    # Timeout: 0 seconds
    # BootOrder: 0000,0006,0004,0005
    # Boot0000* Linux Boot Manager
    # Boot0004* UEFI : Built-in EFI Shell
    # Boot0005* UEFI : LAN : IP6 Intel(R) Ethernet Connection (3) I218-V
    # Boot0006* UEFI : LAN : IP4 Intel(R) Ethernet Connection (3) I218-V
    output = subprocess.check_output([ "efibootmgr" ])

    bo_regex = re.compile("^BootOrder: (?P<boot_order>([a-fA-F0-9]{4},)*[a-fA-F0-9]{4})$", re.MULTILINE)
    lbm_regex = re.compile("^Boot(?P<entry>[a-fA-F0-9]{4})\*? (?P<name>Linux Boot Manager$)", re.MULTILINE)
    ipv4_regex = re.compile("^Boot(?P<entry>[a-fA-F0-9]{4})\*? (?P<name>.*IPv?4.*$)", re.MULTILINE)
    bom_m = bo_regex.search(output)
    if bom_m:
        boot_order = bom_m.groupdict()['boot_order'].split(",")
    else:
        boot_order = []
    print boot_order
    lbm_m = lbm_regex.search(output)
    if not lbm_m:
        raise RuntimeError("Cannot find 'Linux Boot Manager' EFI boot entry")
    lbm = lbm_m.groupdict()['entry']
    lbm_name = lbm_m.groupdict()['name']

    ipv4_m = ipv4_regex.search(output)
    if not ipv4_m:
        raise RuntimeError("Cannot find IPv4 boot entry, enable manually")
    ipv4 = ipv4_m.groupdict()['entry']
    ipv4_name = ipv4_m.groupdict()['name']

    # the first to boot has to be ipv4, then linux boot manager
    
    if lbm in boot_order:
        boot_order.remove(lbm)
    if ipv4 in boot_order:
        boot_order.remove(ipv4)
    boot_order = [ ipv4, lbm ] + boot_order
    print "Changing boot order to %s followed by %s" % (ipv4_name, lbm_name)
    subprocess.check_output([ "efibootmgr", "-o", ",".join(boot_order) ])
    print "Setting next boot to be Linux Boot Manager"
    subprocess.check_output([ "efibootmgr", "-n", lbm ])
    
finally:
    if mounted:
        subprocess.call([ "umount", boot_dev ])
