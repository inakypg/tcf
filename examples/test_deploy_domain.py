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

domain = os.environ.get("DOMAIN")

@tcfl.tc.interconnect("ipv4_addr")
@tcfl.tc.target('linux and boot_interconnect')
class aio(tcfl.tc.tc_c):

    # FIXME move to deploy phase; need to fix things in tc.py so we
    # can use the expecter
    def eval_10_deploy(self, target, ic):

        ic.power.cycle()
        # Deploy
        tcfl.pos.deploy(ic, target, domain)

        # If there are errors, exceptions will come,but otherwise we
        # are here, still in the service OS, so reboot into our new OS
        target.power.cycle()

        # FIXME: HACK -- this should happen after a power cycle?
        # should be a post hack installed by expecters
        # FIXME: do for each console
        tcfl.expecter.console_rx_flush(self.expecter, target, truncate = True)


        # Wait for the OS to boot, login as root in the serial console
        # FIXME This is kinda distro specific and needs to be streamlined
        target.expect(re.compile('login:'))	# wait for "i booted prompt"
        target.send('root')			# login as root, assumes passwordless
        # now that we logged in, change the regex expectation
        target.shell.linux_shell_prompt_regex = re.compile('root@.*# ')
        # and make sure the targe this up and the shell properly configured
        target.shell.up()

        # We don't need the interconnect anymore by-- after we booted!!
        # release it for anyone else -- a TC that needs the
        # interconnect would not do this
        ic.release()
        target.report_pass(domain)

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
