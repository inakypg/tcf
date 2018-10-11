#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Common utilities for test cases
"""

import os
import traceback

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

def domain_deploy(ic, target, domain, domain_seed,
                  # FIXME: ideally these could be defaulted
                  boot_dev = None, root_dev = None,
                  boot_domain_service = "service",
                  sos_prompt = None):

    """

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

    assert isinstance(boot_dev, basestring), \
        "FIXME: specify boot_dev, guessing not supported yet"
    assert isinstance(root_dev, basestring), \
        "FIXME: specify root_dev, guessing not supported yet"

    # FIXME: check ic is powered on?
    target.report_info("rebooting into service domain for flashing")
    target.property_set("boot_domain", boot_domain_service)
    target.power.cycle()

    # Sequence for TCF-live based on Fedora
    if sos_prompt:
        target.shell.linux_shell_prompt_regex = sos_prompt
    target.shell.up()
    target.shell.linux_shell_prompt_regex = "prompt: "
    target.shell.run("PS1='pro''mpt: '")

    # FIXME: take from configuration

    # FIXME: use default dict?
    kws = dict(
        rsync_server = ic.kws['ipv4_addr'],
        domain = domain,
        domain_seed = domain_seed,
        boot_dev = boot_dev,
        root_dev = root_dev,
    )

    # FIXME: recover if not formated
    try:
        # FIXME: act on failing, just reformat and retry, then
        # bail out on failure
        target.report_info("mounting /mnt to image")
        target.shell.run("mount " + root_dev + " /mnt")
        # FIXME: handle /mnt: wrong fs type, bad option, bad
        # superblock on /dev/sda5, missing codepage or helper
        # program, or other error. or errors mounting and just reformat
        target.report_info("mounted /mnt to image")
        if domain_seed:
            target.report_info("rsyncing seed %(domain_seed)s from "
                               "%(rsync_server)s to /mnt" % kws)
            try:
                original_timeout = testcase.expecter.timeout
                testcase.expecter.timeout = 800
                target.shell.run(
                    "time rsync -aX --numeric-ids --delete "
                    "%(rsync_server)s::images/%(domain_seed)s/. /mnt/."
                    % kws)
            finally:
                testcase.expecter.timeout = original_timeout

            # Configure the bootloader
            #
            # We do it by hand -- with shell commands, so it is
            # easy to reproduce by a user typing them

            # FIXME: we are EFI only for now, way easier
            # Make sure we have all the entries for systemd-loader
        target.shell.run("/root/boot-config.py %(domain)s %(boot_dev)s "
                         "%(root_dev)s /mnt/boot /boot" % kws)
        target.shell.run("sync")
        target.shell.run("sync")
        # Now setup the local boot loader to boot off that
        target.property_set("boot_domain", domain)
    except Exception as e:
        target.report_info("BUG? exception %s: %s %s" %
                           (type(e).__name__, e, traceback.format_exc()))
        raise
    finally:
        target.shell.run("umount /mnt")

    target.report_info("deployed %(domain_seed)s to %(root_dev)s" % kws)
