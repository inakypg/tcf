#! /usr/bin/python
#
# Add to your config:
#
# tcfl.config.url_add('https://jfsotc09.jf.intel.com:5001',
#                    ssl_ignore = True)
#
#
# $ [DOMAIN_VERSION=91] tcf run -v test_deploy_domain.py

import os
import re

import tcfl.tc
import tcfl.tl
import tcfl.pos

image = os.environ["IMAGE"]

@tcfl.tc.interconnect("ipv4_addr")
@tcfl.tc.target('pos_capable')
class aio(tcfl.tc.tc_c):

    # FIXME move to deploy phase; need to fix things in tc.py so we
    # can use the expecter
    def eval_10_deploy(self, target, ic):

        ic.power.cycle()
        # Deploy
        tcfl.pos.deploy_image(ic, target, image)

        # If there are errors, exceptions will come,but otherwise we
        # are here, still in the service OS, so reboot into our new OS
        target.power.cycle()

        # our shell prompt will look like this...
        target.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        # Wait for the OS to boot, login as root in the serial
        # console, configure the shell
        target.shell.up(user = 'root')

        # We don't need the interconnect anymore by-- after we booted!!
        # release it for anyone else -- a TC that needs the
        # interconnect would not do this
        ic.release()
        target.report_pass("Deployed %s" % image)

    #
    # Run our tests
    #
    def eval_20(self, target):
        # run the command that launches the tests, wait for the shell
        # prompt; if it fails, this will raise an exception
        # FIXME: we need hooks to detect kernel panics, oopses, etc
        target.shell.run("echo I booted", "I booted")

    def teardown(self):
        tcfl.tl.console_dump_on_failure(self)
