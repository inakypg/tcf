#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Common utilities for test cases
"""

import operator
import os
import random
import re
import traceback

import Levenshtein

import tcfl.tc

#! Place where the Zephyr tree is located
# Note we default to empty string so it can be pased
ZEPHYR_BASE = os.environ.get(
    'ZEPHYR_BASE',
    '__environment_variable_ZEPHYR_BASE__not_exported__')

def zephyr_tags():
    """
    Evaluate the build environment and make sure all it is needed to
    build Zephyr apps is in place.

    If not, return a dictionary defining a *skip* tag with the reason
    that can be fed directly to decorator :func:`tcfl.tc.tags`; usage:

    >>> import tcfl.tc
    >>> import qal
    >>>
    >>> @tcfl.tc.tags(**qal.zephyr_tests_tags())
    >>> class some_test(tcfl.tc.tc_c):
    >>>     ...
    """
    tags = {}
    zephyr_vars = set([ 'ZEPHYR_BASE', 'ZEPHYR_GCC_VARIANT',
                        'ZEPHYR_TOOLCHAIN_VARIANT' ])
    zephyr_vars_missing = zephyr_vars - set(os.environ.keys())
    if 'ZEPHYR_GCC_VARIANT' in zephyr_vars_missing \
       and 'ZEPHYR_TOOLCHAIN_VARIANT' in set(os.environ.keys()):
        # ZEPHYR_GCC_VARIANT deprecated -- always remove it
        # TOOLCHAIN_VARIANT (the new form) is set
        zephyr_vars_missing.remove('ZEPHYR_GCC_VARIANT')
    if zephyr_vars_missing:
        tags['skip'] = ",".join(zephyr_vars_missing) + " not exported"
    return tags


def console_dump_on_failure(testcase):
    """
    If a testcase has errored, failed or blocked, dump the consoles of
    all the targets.

    :param tcfl.tc.tc_c testcase: testcase whose targets' consoles we
      want to dump

    Usage: in a testcase's teardown function:

    >>> import tcfl.tc
    >>> import tcfl.tl
    >>>
    >>> class some_test(tcfl.tc.tc_c):
    >>>     ...
    >>>
    >>>     def teardown_SOMETHING(self):
    >>>         tcfl.tl.console_dump_on_failure(self)
    """
    assert isinstance(testcase, tcfl.tc.tc_c)
    if not testcase.result_eval.failed \
       and not testcase.result_eval.errors \
       and not testcase.result_eval.blocked:
        return
    for target in testcase.targets.values():
        if not hasattr(target, "console"):
            continue
        if testcase.result_eval.failed:
            reporter = target.report_fail
            reporter("console dump due to failure")
        elif testcase.result_eval.errors:
            reporter = target.report_error
            reporter("console dump due to errors")
        else:
            reporter = target.report_blck
            reporter("console dump due to blockage")
        for line in target.console.read().split('\n'):
            reporter("console: " + line.strip())


def setup_verify_slip_feature(zephyr_client, zephyr_server, _ZEPHYR_BASE):
    """
    The Zephyr kernel we use needs to support
    CONFIG_SLIP_MAC_ADDR, so if any of the targets needs SLIP
    support, make sure that feature is Kconfigurable
    Note we do this after building, because we need the full
    target's configuration file.

    :param tcfl.tc.target_c zephyr_client: Client Zephyr target

    :param tcfl.tc.target_c zephyr_server: Client Server target

    :param str _ZEPHYR_BASE: Path of Zephyr source code

    Usage: in a testcase's setup methods, before building Zephyr code:

    >>>     @staticmethod
    >>>     def setup_SOMETHING(zephyr_client, zephyr_server):
    >>>         tcfl.tl.setup_verify_slip_feature(zephyr_client, zephyr_server,
                                                  tcfl.tl.ZEPHYR_BASE)

    Look for a complete example in
    :download:`../examples/test_network_linux_zephyr_echo.py`.
    """
    assert isinstance(zephyr_client, tcfl.tc.target_c)
    assert isinstance(zephyr_server, tcfl.tc.target_c)
    client_cfg = zephyr_client.zephyr.config_file_read()
    server_cfg = zephyr_server.zephyr.config_file_read()
    slip_mac_addr_found = False
    for file_name in [
            os.path.join(_ZEPHYR_BASE, "drivers", "net", "Kconfig"),
            os.path.join(_ZEPHYR_BASE, "drivers", "slip", "Kconfig"),
    ]:
        if os.path.exists(file_name):
            with open(file_name, "r") as f:
                if "SLIP_MAC_ADDR" in f.read():
                    slip_mac_addr_found = True

    if ('CONFIG_SLIP' in client_cfg or 'CONFIG_SLIP' in server_cfg) \
       and not slip_mac_addr_found:
        raise tcfl.tc.blocked_e(
            "Can't test: your Zephyr kernel in %s lacks support for "
            "setting the SLIP MAC address via configuration "
            "(CONFIG_SLIP_MAC_ADDR) -- please upgrade"
            % _ZEPHYR_BASE, dict(dlevel = -1)
        )

def teardown_targets_power_off(testcase):
    """
    Power off all the targets used on a testcase.

    :param tcfl.tc.tc_c testcase: testcase whose targets we are to
      power off.

    Usage: in a testcase's teardown function:

    >>> import tcfl.tc
    >>> import tcfl.tl
    >>>
    >>> class some_test(tcfl.tc.tc_c):
    >>>     ...
    >>>
    >>>     def teardown_SOMETHING(self):
    >>>         tcfl.tl.teardown_targets_power_off(self)

    Note this is usually not necessary as the daemon will power off
    the targets when cleaning them up; usually when a testcase fails,
    you want to keep them on to be able to inspect them.
    """
    assert isinstance(testcase, tcfl.tc.tc_c)
    for dummy_twn, target  in reversed(list(testcase.targets.iteritems())):
        target.power.off()

def tcpdump_enable(ic):
    """
    Ask an interconnect to capture IP traffic with TCPDUMP

    Note this is only possible if the server to which the interconnect
    is attached has access to it; if the interconnect is based on the
    :class:vlan_pci driver, it will support it.

    Note the interconnect *must be* power cycled after this for the
    setting to take effect. Normally you do this in the *start* method
    of a multi-target testcase

    >>> def start(self, ic, server, client):
    >>>    tcfl.tl.tcpdump_enable(ic)
    >>>    ic.power.cycle()
    >>>    ...
    """
    assert isinstance(ic, tcfl.tc.target_c)
    ic.property_set('tcpdump', ic.kws['tc_hash'] + ".cap")


def tcpdump_collect(ic, filename = None):
    """
    Collects from an interconnect target the tcpdump capture

    .. warning: this will power off the interconnect!

    :param tcfl.tc.target_c ic: interconnect target
    :param str filename: (optional) name of the local file where to
        copy the tcpdump data to; defaults to
        *report-RUNID:HASHID-REP.tcpdump* (where REP is the repetition
        count)
    """
    assert isinstance(ic, tcfl.tc.target_c)
    assert filename == None or isinstance(filename, basestring)
    if filename == None:
        filename = \
            "report-%(runid)s:%(tc_hash)s" % ic.kws \
            + "-%d" % (ic.testcase.eval_count + 1) \
            + ".tcpdump"
    ic.power.off()		# ensure tcpdump flushes
    ic.broker_files.dnload(ic.kws['tc_hash'] + ".cap", filename)
    ic.report_info("tcpdump available in file %s" % filename)

def pos_partition(target, device):
    # /dev/SOMETHING to -> SOMETHING
    device_basename = os.path.basename(device)

    # in case we autoswapped on anything
    target.shell.run('swapoff -a || true')

    output = target.shell.run(
        'cat /sys/block/%s/size /sys/block/%s/queue/physical_block_size'
        % (device_basename, device_basename), output = True)
    regex = re.compile(r"(?P<blocks>[0-9]+)\r\n"
                       r"(?P<block_size>[0-9]+)\r\n", re.MULTILINE)
    m = regex.search(output)
    if not m:
        raise tcfl.tc.blocked_e(
            "can't find block and physical blocksize",
            { 'output': output, 'pattern': regex.pattern,
              'target': target }
        )
    blocks = int(m.groupdict()['blocks'])
    block_size = int(m.groupdict()['block_size'])
    size_gb = blocks * block_size / 1024 / 1024 / 1024
    target.report_info("%s is %d GiB in size" % (device, size_gb))

    partsizes = target.kws.get('pos_partsizes', None)
    if partsizes == None:
        raise tcfl.tc.blocked_e(
            "Can't partition target, it doesn't "
            "specify pos_partsizes tag",
            { 'target': target } )
    partsize_l = partsizes.split(":")
    partsize_l = [ int(_partsize) for _partsize in partsize_l ]
    boot_size = partsize_l[0]
    swap_size = partsize_l[1]
    scratch_size = partsize_l[2]
    root_size = partsize_l[3]

    # note we set partition #0 as boot
    cmdline = """parted -a optimal -ms %(device)s unit GiB \
mklabel gpt \
mkpart primary fat32 0%% %(boot_size)s \
set 1 boot on \
mkpart primary linux-swap %(boot_size)s %(swap_end)s \
mkpart primary ext4 %(swap_end)s %(scratch_end)s \
""" % dict(
    device = device,
    boot_size = boot_size,
    swap_end = boot_size + swap_size,
    scratch_end = boot_size + swap_size + scratch_size,
)
    offset = boot_size + swap_size + scratch_size
    root_devs = []	# collect the root devices
    pid = 4
    while offset + root_size < size_gb:
        cmdline += ' mkpart primary ext4 %d %d' % (offset, offset + root_size)
        offset += root_size
        root_devs.append(device_basename + target.kws['p_prefix']
                         + "%d" % pid)
        pid += 1

    target.shell.run(cmdline)
    # Now set the root device information, so we can pick stuff to
    # format quick
    for root_dev in root_devs:
        target.property_set('pos_root_' + root_dev, "EMPTY")

    # Re-read partition tables
    target.shell.run('partprobe %s' % device)

    # now format filesystems
    #
    # note we only format the system boot partition (1), the linux
    # swap(2) and the linux scratch space (3)
    boot_dev = device + target.kws['p_prefix'] + "1"
    swap_dev = device + target.kws['p_prefix'] + "2"
    home_dev = device + target.kws['p_prefix'] + "3"
    target.shell.run("mkfs.vfat -F32 -n TCF-BOOT " + boot_dev)
    target.shell.run("mkswap -L tcf-swap " + swap_dev)
    target.shell.run("mkfs.ext4 -FqL tcf-scratch " + home_dev)

def _pos_linux_guess_from_lecs(target):
    """
    Setup a Linux kernel to boot using Gumniboot
    """
    # ignore errors if it does not exist
    lecs = target.shell.run(
        r"find /mnt/boot/loader/entries -type f -iname \*.conf || true",
        output = True)
    # this returns something like
    #
    # find /mnt/boot/loader/entries -type f -iname \*.conf
    # /mnt/boot/loader/entries/Clear-linux-native-4.18.13-644.conf
    # /mnt/boot/loader/entries/Something-else.conf
    # 10 $
    #
    # Filter just the output we care for
    lecl = []
    for lec in lecs.split("\n"):
        lec = lec.strip()
        if not lec.startswith("/mnt/boot/loader/entries/"):
            continue
        lecl.append(lec)
        target.report_info("Loader Entry found: %s" % lec, dlevel = 1)
    if len(lecl) > 1:
        raise tcfl.tc.blocked_e(
            "multiple loader entries in /boot, do not "
            "know which one to use: " + " ".join(lecl),
            dict(target = target))
    elif len(lecl) == 0:
        return None, None, None
    # fallthrough, only one entry
    lec = lecl[0]
    output = target.shell.run('cat %s' % lec, output = True)
    kernel = None
    initrd = None
    options = None
    # read a loader entry, extract the kernel, initramfs and options
    # thanks Loader Entry Specification for making them single liners...
    dibs_regex = re.compile(r"^\s*(?P<command>linux|initrd|efi|options)\s+"
                            "(?P<value>[^\n]+)\n?")
    for line in output.splitlines():
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
            initrd = value
        elif command == 'options':
            options = value

    return kernel, initrd, options

def _pos_linux_guess_from_boot(target):
    """
    Given a list of files (normally) in /boot, decide which ones are
    Linux kernels and initramfs; select the latest version
    """
    output = target.shell.run("ls -1 /mnt/boot", output = True)
    kernel_regex = re.compile("(initramfs|initrd|bzImage|vmlinuz)(-(.*))?")
    kernel_versions = {}
    initramfs_versions = {}
    for line in output.split('\n'):
        m = kernel_regex.match(line)
        if not m:
            continue
        file_name = m.groups()[0]
        kver = m.groups()[1]
        if kver and ("rescue" in kver or "kdump" in kver):
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
        raise tcfl.tc.blocked_e(
            "more than one Linux kernel in /boot; I don't know "
            "which one to use: " + " ".join(kernel_versions),
            dict(target = target, output = output))
    else:
        return None, None, ""

def _pos_linux_guess(target):
    """
    Setup a Linux kernel to boot using Gumniboot
    """
    kernel, initrd, options = _pos_linux_guess_from_lecs(target)
    if kernel:
        return kernel, initrd, options
    kernel, initrd, options = _pos_linux_guess_from_boot(target)
    if kernel:
        return kernel, initrd, options
    return None, None, None

def _pos_efibootmgr_setup(target):
    # Now make sure the new entry is after IPv4, as we use IPv4's boot
    # to redirect to the POS or to localboot
    #
    # $ efibootmgr
    # BootCurrent: 0006
    # Timeout: 0 seconds
    # BootOrder: 0000,0006,0004,0005
    # Boot0000* Linux Boot Manager
    # Boot0004* UEFI : Built-in EFI Shell
    # Boot0005* UEFI : LAN : IP6 Intel(R) Ethernet Connection (3) I218-V
    # Boot0006* UEFI : LAN : IP4 Intel(R) Ethernet Connection (3) I218-V
    output = target.shell.run("efibootmgr", output = True)
    bo_regex = re.compile(r"^BootOrder: "
                          "(?P<boot_order>([a-fA-F0-9]{4},)*[a-fA-F0-9]{4})$",
                          re.MULTILINE)
    # this one we added before calling this function with "bootctl
    # install"
    lbm_regex = re.compile(r"^Boot(?P<entry>[a-fA-F0-9]{4})\*? "
                           "(?P<name>Linux Boot Manager$)", re.MULTILINE)
    ipv4_regex = re.compile(r"^Boot(?P<entry>[a-fA-F0-9]{4})\*? "
                            # PXEv4 is QEMU's UEFI
                            # .*IPv4 are some NUCs I've found
                            "(?P<name>(UEFI PXEv4|.*IPv?4).*$)", re.MULTILINE)
    bom_m = bo_regex.search(output)
    if bom_m:
        boot_order = bom_m.groupdict()['boot_order'].split(",")
    else:
        boot_order = []
    target.report_info("current boot_order: %s" % boot_order)
    lbm_m = lbm_regex.search(output)
    if not lbm_m:
        raise tcfl.tc.blocked_e(
            "Cannot find 'Linux Boot Manager' EFI boot entry",
            dict(target = target, output = output))
    lbm = lbm_m.groupdict()['entry']
    lbm_name = lbm_m.groupdict()['name']

    ipv4_m = ipv4_regex.search(output)
    if not ipv4_m:
        raise tcfl.tc.blocked_e(
            # FIXME: improve message to be more helpful and point to docz
            "Cannot find IPv4 boot entry, enable manually",
            dict(target = target, output = output))
    ipv4 = ipv4_m.groupdict()['entry']
    ipv4_name = ipv4_m.groupdict()['name']

    # the first to boot has to be ipv4, then linux boot manager

    if lbm in boot_order:
        boot_order.remove(lbm)
    if ipv4 in boot_order:
        boot_order.remove(ipv4)
    boot_order = [ ipv4, lbm ] + boot_order
    target.report_info("Changing boot order to %s followed by %s"
                       % (ipv4_name, lbm_name))
    target.shell.run("efibootmgr -o " + ",".join(boot_order))
    # Next time we reboot we want to go straight to our deployment
    target.report_info("Setting next boot to be Linux Boot Manager")
    target.shell.run("efibootmgr -n " + lbm)


def pos_boot_config(target, root_part_dev,
                    linux_kernel_file = None,
                    linux_initrd_file = None,
                    linux_options = None):
    boot_dev = target.kws['pos_boot_dev']
    # were we have mounted the root partition
    root_dir = "/mnt"

    # If we didn't specify a Linux kernel, try to guess
    if linux_kernel_file == None:
        linux_kernel_file, _linux_initrd_file, _linux_options = \
            _pos_linux_guess(target)
    if linux_initrd_file == None:
        linux_initrd_file = _linux_initrd_file
    if linux_options == None:
        linux_options = _linux_options
    if linux_kernel_file == None:
        raise tcfl.tc.blocked_e(
            "Cannot guess a Linux kernel to boot")
    # remove absolutization (some specs have it), as we need to copy from
    # mounted filesystems
    if os.path.isabs(linux_kernel_file):
        linux_kernel_file = linux_kernel_file[1:]
    if linux_initrd_file and os.path.isabs(linux_initrd_file):
        linux_initrd_file = linux_initrd_file[1:]


    # /boot EFI system partition is always /dev/DEVNAME1 (first
    # partition), we partition like that
    # FIXME: we shouldn't harcode this
    boot_part_dev = boot_dev + target.kws['p_prefix'] + "1"

    kws = dict(
        boot_dev = boot_dev,
        boot_part_dev = boot_part_dev,
        root_part_dev = root_part_dev,
        root_dir = root_dir,
        linux_kernel_file = linux_kernel_file,
        linux_kernel_file_basename = os.path.basename(linux_kernel_file),
        linux_initrd_file = linux_initrd_file,
        linux_options = linux_options,
    )
    if linux_initrd_file:
        kws['linux_initrd_file_basename'] = os.path.basename(linux_initrd_file)
    else:
        kws['linux_initrd_file_basename'] = None

    kws.update(target.kws)

    if linux_options:
        #
        # Maybe mess with the Linux boot options
        #
        target.report_info("linux cmdline options: %s" % linux_options)
        # FIXME: can this come from config?
        linux_options_replace = {
            # we want to use hard device name rather than LABELS/UUIDs, as
            # we have reformated and those will have changed
            "root": "/dev/%(root_part_dev)s" % kws
        }

        # FIXME: can this come from config?
        # We harcode a serial console on the device where we know the
        # framework is listening
        linux_options_append = [
            "console=%(linux_serial_console_default)s,115200n8" % kws
        ]

        for option in linux_options_append:
            if not option in linux_options:
                linux_options += " " + option

        for option, value in linux_options_replace.iteritems():
            regex = re.compile(r"\b" + option + r"=\S+")
            if regex.search(linux_options):
                linux_options = re.sub(
                    regex,
                    option + "=" + linux_options_replace[option],
                    linux_options)
            else:
                linux_options += " " + option + "=" + value

        kws['linux_options'] = linux_options
        target.report_info("linux cmdline options (modified): %s"
                           % linux_options)

    # Now generate the UEFI system partition that will boot the
    # system; we always override it, so we don't need to decide if it
    # is corrupted or whatever; we'll mount it in /boot (which now is
    # the POS /boot)

    # mkfs.vfat /boot, mount it
    target.report_info("mounting %(boot_part_dev) in /boot")
    target.shell.run("mkfs.vfat -F32 /dev/%(boot_part_dev)s" % kws)
    target.shell.run("sync")
    target.shell.run("mount /dev/%(boot_part_dev)s /boot" % kws)
    target.shell.run("mkdir -p /boot/loader/entries")
    target.shell.run("""\
cat <<EOF > /boot/loader/entries/README
This boot configuration was written by TCF's AFAPLI client hack; it is
meant to boot multiple Linux distros coexisting in the
same drive.

Uses systemd-boot/gumniboot; partition one is /boot (EFI System
Partition), where this file is located. Partition 2 is dedicated to
swap. Partition 3 is dedicated to home/scratch, which can be wiped
and reset everytime a new test is run.

Partitions 4-on are different root filesystems which can be reused by
the system as needed for booting different domains (aka: distros
configured in particular ways).
EOF
    """)

    # Now copy all the files needed to boot to the root of the EFI
    # system partition mounted in /boot; remember they are in /mnt/,
    # our root partition
    # use dd instead of cp, it won't ask to override and such
    target.shell.run("dd if=/mnt/boot/%(linux_kernel_file)s "
                     "of=/boot/%(linux_kernel_file_basename)s" % kws)
    target.shell.run("""\
cat <<EOF > /boot/loader/entries/tcf-boot.conf
title TCF-driven local boot
linux /%(linux_kernel_file_basename)s
EOF
""" % kws)
    if kws.get(linux_initrd_file, None):
        target.shell.run("dd if=/mnt/boot/%(linux_initrd_file)s "
                         "of=/boot/%(linux_initrd_file_basename)s" % kws)
        target.shell.run("""\
cat <<EOF >> /boot/loader/entries/tcf-boot.conf
initrd /%(linux_initrd_file_basename)s
EOF
""" % kws)
    target.shell.run("""\
cat <<EOF >> /boot/loader/entries/tcf-boot.conf
options %(linux_options)s
EOF
""" % kws)

    # Cleanup previous install of the bootloader, setup new one
    # we don't care if we fail to remote, maybe not yet installed
    target.shell.run("bootctl remove || true")
    target.shell.run("bootctl install")

    # Now mess with the EFIbootmgr
    # FIXME: make this a function and a configuration option (if the
    # target does efibootmgr)
    _pos_efibootmgr_setup(target)
    # umount only if things go well
    # Shall we try to unmount in case of error? nope, we are going to
    # have to redo the whole thing anyway, so do not touch it, in case
    # we are jumping in for manual debugging
    target.shell.run("umount /dev/%(boot_part_dev)s" % kws)

def _pos_seed_match(lp, goal):
    """
    Given two seed specifications, return the most similar one

    >>> lp = {
    >>>     'part1': 'clear:live:25550::x86-64',
    >>>     'part2': 'fedora:workstation:28::x86',
    >>>     'part3': 'rtk::91',
    >>>     'part4': 'rtk::90',
    >>>     'part5': 'rtk::114',
    >>> }
    >>> _pos_seed_match(lp, "rtk::112")
    >>> ('part5', 0.933333333333, 'rtk::114')

    """
    def _entry_to_tuple(i):
        distro = ""
        spin = ""
        version = ""
        pl = ""
        arch = ""
        il = i.split(":")
        if len(il) > 0:
            distro = il[0]
        if len(il) > 1:
            spin = il[1]
        if len(il) > 2:
            version = il[2]
        if len(il) > 3:
            pl = il[3]
        if len(il) > 4:
            arch = il[4]
        return distro, spin, version, pl, arch

    goall = _entry_to_tuple(goal)
    scores = {}
    for part_name, seed in lp.iteritems():
        score = 0
        seedl = _entry_to_tuple(str(seed))

        if seedl[0] == goall[0]:
            # At least we want a distribution match for it to be
            # considered
            scores[part_name] = Levenshtein.seqratio(goall, seedl)
        else:
            scores[part_name] = 0
    selected, score = max(scores.iteritems(), key = operator.itemgetter(1))
    return selected, score, lp[selected]

def domain_deploy(ic, target, domain,
                  # FIXME: ideally these could be defaulted
                  boot_dev = None, root_dev = None,
                  boot_domain_service = "service",
                  sos_prompt = None,
                  partitioning_fn = pos_partition,
                  mkfs_cmd = "mkfs.ext4 -j %(root_dev)s"):

    """
    Deploy a domain to a target using the Provisioning OS

    :param str boot_dev: (optional) which is the boot device to use,
      where the boot loader needs to be installed in a boot
      partition. e.g.: ``sda`` for */dev/sda* or ``mmcblk01`` for
      */dev/mmcblk01*.

      Defaults to the value of the ``pos_boot_dev`` tag.

    Domain spec DOMAIN:SPIN:VERSION:SUBVERSION:SUBVERSION

    FIXME:
     - fix to autologing serial console?
     - do a couple retries if fails?
     - increase in property bd.stats.client.sos_boot_failures and
       bd.stats.client.sos_boot_count (to get a baseline_
     - tag bd.stats.last_reset to DATE
    Note: you might want the interconnect power cycled

    """
    testcase = target.testcase

    # What is our boot device?
    if boot_dev:
        assert isinstance(boot_dev, basestring), 'boot_dev must be a string'
    else:
        boot_dev = target.kws.get('pos_boot_dev', None)
        if boot_dev == None:
            raise tcfl.tc.blocked_e(
                "Can't guess boot_dev (no `pos_boot_dev` tag available)",
                { 'target': target } )
    boot_dev = "/dev/" + boot_dev

    # what is out root device?
    if root_dev:
        assert isinstance(root_dev, basestring), 'root_dev must be a string'
    else:
        # HACK: /dev/[hs]d* do partitions as /dev/[hs]dN, where as mmc and
        # friends add /dev/mmcWHATEVERpN. Seriously...
        device = boot_dev
        if device.startswith("/dev/hd") \
           or device.startswith("/dev/sd") \
           or device.startswith("/dev/vd"):
            target.kws['p_prefix'] = ""
        else:
            target.kws['p_prefix'] = "p"

        partl = {}
        empties = []
        for tag, value in target.rt.iteritems():
            if not tag.startswith("pos_root_"):
                continue
            dev_basename = tag.replace("pos_root_", "")
            dev_name = "/dev/" + dev_basename
            if value == 'EMPTY':
                empties.append(dev_name)
            else:
                partl[dev_name] = value

        root_part_dev, score, seed = _pos_seed_match(partl, domain)
        if score == 0:
            # none is a good match, find an empty one...if there are
            # non empty, just any
            if empties:
                root_part_dev = random.choice(empties)
                target.report_info("%s: picked up empty root partition"
                                   % root_part_dev)
            else:
                # FIXME: collect least-used partition data?
                root_part_dev = random.choice(partl.keys())
                target.report_info(
                    "%s: picked up random partition because none of the "
                    "existing installed ones was a good match and there "
                    "are no empty ones" % root_part_dev)
        else:
            target.report_info("picked up root partition %s for %s "
                               "due to a %.02f similarity with %s"
                               % (root_part_dev, seed, score, seed))
    # FIXME: check ic is powered on?
    target.report_info("rebooting into service domain for flashing")
    target.property_set("boot_domain", boot_domain_service)
    target.power.cycle()

    # Sequence for TCF-live based on Fedora
    if sos_prompt:
        target.shell.linux_shell_prompt_regex = sos_prompt
    target.shell.up()

    # FIXME: use default dict?
    root_part_dev_base = os.path.basename(root_part_dev)
    kws = dict(
        rsync_server = ic.kws['ipv4_addr'],
        domain = domain,
        boot_dev = boot_dev,
        root_part_dev = root_part_dev,
        root_part_dev_base = root_part_dev_base,
    )

    # FIXME: verify root partitioning is the right one and recover if
    # not
    try:
        # FIXME: act on failing, just reformat and retry, then
        # bail out on failure
        target.report_info("mounting /mnt to image")
        for _try_count in range(3):
            # don't let it fail or it will raise an exception, so we
            # print FAILED in that case to look for stuff; note the
            # double apostrophe trick so the regex finder doens't trip
            # on the command
            output = target.shell.run(
                "mount %(root_part_dev)s /mnt || echo FAI''LED" % kws,
                output = True)
            # What did we get?
            if 'FAILED' in output:
                if 'mount: /mnt: special device ' + root_part_dev \
                   + ' does not exist.' in output:
                    partitioning_fn(target, boot_dev)
                elif 'mount: /mnt: wrong fs type, bad option, ' \
                   'bad superblock on ' + root_part_dev + ', missing ' \
                   'codepage or helper program, or other error.' in output:
                    # ok, this means probably the partitions are not
                    # formatted; FIXME: support other filesystemmakeing?
                    target.shell.run(mkfs_cmd % kws)
                else:
                    raise tcfl.tc.blocked_e(
                        "Can't recover unknown error condition: %s" % output,
                        dict(target = target))
            else:
                target.report_info("mounted /mnt to image")
                break	# it worked, we are done
            # fall through, retry
        else:
            raise tcfl.tc.blocked_e(
                "Tried to deploy too many times and failed",
                dict(target = target))
        if domain:
            target.report_info("rsyncing seed %(domain)s from "
                               "%(rsync_server)s to /mnt" % kws)
            try:
                original_timeout = testcase.expecter.timeout
                testcase.expecter.timeout = 800
                target.shell.run(
                    "time rsync -aX --numeric-ids --delete "
                    "%(rsync_server)s::images/%(domain)s/. /mnt/."
                    % kws)
                target.property_set('pos_root_' + root_part_dev_base, domain)
            finally:
                testcase.expecter.timeout = original_timeout

            # Configure the bootloader
            #
            # We do it by hand -- with shell commands, so it is
            # easy to reproduce by a user typing them

            # FIXME: we are EFI only for now, way easier
            # Make sure we have all the entries for systemd-loader
            pos_boot_config(target, root_part_dev_base)
        target.shell.run("sync")
        # Now setup the local boot loader to boot off that
        target.property_set("boot_domain", domain)
    except Exception as e:
        target.report_info("BUG? exception %s: %s %s" %
                           (type(e).__name__, e, traceback.format_exc()))
        raise
    finally:
        target.shell.run("umount /mnt")

    target.report_info("deployed %(domain)s to %(root_part_dev)s" % kws)
