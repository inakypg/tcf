#! /usr/bin/python
import os

import tcfl.tc

domain = os.environ["DOMAIN"]
domain_part = os.environ["DOMAIN_PART"]
domain_seed = os.environ.get("DOMAIN_SEED", None)

@tcfl.tc.interconnect()
@tcfl.tc.target()
class deploy_domain(tcfl.tc.tc_c):

    # FIXME move to deploy phase; need to fix things in tc.py so we
    # can use the expecter
    
    def eval(self, target, ic):
        
        target.report_info("rebooting into service domain for flashing")
        target.property_set("boot_domain", "service")
        target.power.cycle()
        target.shell.up()

        # Trap the shell to complain loud if a command fails, and catch it
        target.send("trap 'echo ERROR-IN-SHELL' ERR")
        target.on_console_rx("ERROR-IN-SHELL", result = 'fail', timeout = False)

        rsync_server = ic.kws['ipv4_addr']
        
        # FIXME: recover if not formated
        try:
            target.report_info("mounting /boot and /mnt")
            # FIXME: act on
            # [   15.500607] FAT-fs (vdd1): Volume was not properly unmounted. Some data may be corrupt. Please run fsck.
            target.shell.run("mount /dev/disk/by-partlabel/tcf-boot /boot")
            # FIXME: act on failing, just reformat and retry, then
            # bail out on failure
            target.shell.run("mount /dev/disk/by-partlabel/tcf-root-%s /mnt"
                             % domain_part)
            if domain_seed:
                target.report_info("rsyncing seed %s to /mnt" % domain_seed)
                target.shell.run(
                    "time rsync -a --delete %s::images/%s/. /mnt/."
                    % (rsync_server, domain))
                # fugly, need way better semantics -- paramiko? pypy?
                # however, this runs contrary to clear steps that the
                # user can reproduce typing
                target.shell.run("[ -r /mnt/boot/bzImage ] && cp -f /mnt/boot/bzImage /boot/vmlinuz-%s" % domain)
                target.shell.run("[ -r /mnt/boot/vmlinuz ] && cp -f /mnt/boot/bzImage /boot/vmlinuz-%s" % domain)
                target.shell.run("[ -r /mnt/boot/initramfs ] && cp -f /mnt/boot/initramfs /boot/initramfs-%s" % domain)
            console_so_far = target.console.read()
            target.property_set("boot_domain", domain)
        finally:
            target.shell.run("umount /dev/disk/by-partlabel/tcf-boot")
            target.shell.run("umount /dev/disk/by-partlabel/tcf-root-%s"
                             % domain_part)
