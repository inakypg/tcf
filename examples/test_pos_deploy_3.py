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
@tcfl.tc.target('pos_capable')
@tcfl.tc.target('pos_capable')
class _test(tcfl.tc.tc_c):
    """
    Provision three PC targets at the same time with the Provisioning OS
    """

    @tcfl.tc.serially()
    def deploy(self, ic):
        ic.power.cycle()
        ic.report_pass("powered on")

    @tcfl.tc.concurrently()
    def deploy_10_target(self, target):
        tcfl.pos.deploy_image(self.ic, target, image)
        target.report_pass("DEPLOYED")
        target.power.cycle()
        target.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        target.shell.up(user = 'root')

    @tcfl.tc.concurrently()
    def deploy_10_target1(self, target1):
        tcfl.pos.deploy_image(self.ic, target1, image)
        target1.report_pass("DEPLOYED")
        target1.power.cycle()
        target1.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        target1.shell.up(user = 'root')

    @tcfl.tc.concurrently()
    def deploy_10_target2(self, target2):
        tcfl.pos.deploy_image(self.ic, target2, image)
        target2.report_pass("DEPLOYED")
        target2.power.cycle()
        target2.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        target2.shell.up(user = 'root')

    def eval(self, target, target1, target2):
        target.shell.run("echo I booted", "I booted")
        target1.shell.run("echo I booted", "I booted")
        target2.shell.run("echo I booted", "I booted")

    def teardown(self):
        tcfl.tl.console_dump_on_failure(self)
