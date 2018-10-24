#! /usr/bin/python
#
# Copyright (c) 2018 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable = missing-docstring

import os
import re

import tcfl.tc
import tcfl.tl
import tcfl.pos

image = os.environ["IMAGE"]

@tcfl.tc.interconnect("ipv4_addr")
@tcfl.tc.target('pos_capable')
class _test(tcfl.tc.tc_c):

    def deploy(self, ic, target):
        # ensure network, DHCP, TFTP, etc are up and deploy
        ic.power.on()
        tcfl.pos.deploy_image(ic, target, image)

    def start(self, ic, target):
        # fire up the target, wait for a login prompt
        target.power.cycle()
        target.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        target.shell.up(user = 'root')
        target.report_pass("Deployed %s" % image)
        # release here so we had the daemon control where we boot to
        ic.release()

    def eval(self):
        # do our test
        target.shell.run("echo I booted", "I booted")

    def teardown(self):
        tcfl.tl.console_dump_on_failure(self)
