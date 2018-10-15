#! /usr/bin/python2
#
# All notes and documentation go to afapli/README.rst

import os
import pwd
import shutil
import stat
import subprocess

import commonl
import ttbl
import ttbl.config

# FIXME: config setting ttbd-staging
tftp_prefix = "ttbd-staging"
# FIXME config setting
tftp_dir = "/var/lib/tftpboot"
# FIXME config setting
syslinux_path = "/usr/share/syslinux"

class pci(ttbl.tt_power_control_impl):

    class error_e(Exception):
        pass

    class start_e(error_e):
        pass

    # Yeaaaaah, this is kinda overkill
    class dhcpd_start_e(start_e):
        pass

    class tftpd_start_e(start_e):
        pass


    dhcpd_path = "/usr/sbin/dhcpd"
    tftpd_path = "/usr/sbin/in.tftpd"

    """

    This class implements a power control unit that can be made part
    of a power rail for a network interconnect.

    When turned on, it would start daemons that provide services on
    the network, like DHCP or TFTP.

    With a configuration such as::

      import ttbl.dhcp

      ttbl.config.targets['nwa'].pc_impl.append(ttbl.dhcp.pci(
          "192.168.97.1",
          "192.168.97.0", "255.255.255.0",
          "192.168.97.10", "192.168.97.20",
          {
              "52:54:00:06:28:d7": dict(
                  ipv4_addr = "192.168.97.13",
                  Zephyr_minnow = dict(
                      kernel = "/some/path/z/build-hello-world-minnowboard/zephyr/zephyr.bin"),
              ),
          }, debug = True))


    .. warning:: this is incomplete!

    - Ensure firewall is open for UDP 67, 68, 69
    - FIXME: split in two PCIs, one DHCP, one TFTP, hook would be
      needed for DHCP to know TFTP is up
    """

    def __init__(self,
                 if_addr,
                 if_net,
                 if_len,
                 ip_addr_range_bottom,
                 ip_addr_range_top,
                 mac_ip_map = None,
                 allow_unmapped = False,
                 debug = False,
                 ip_mode = 4):
        assert ip_mode in (4, 6)
        ttbl.tt_power_control_impl.__init__(self)
        self.allow_unmapped = allow_unmapped
        if mac_ip_map == None:
            self._mac_ip_map = {}
        else:
            self._mac_ip_map = mac_ip_map

        # FIXME: move to power_on_do, to get this info from target's tags
        self._params = dict(
            tftp_prefix = tftp_prefix,
            if_net = if_net,
            if_addr = if_addr,
            if_len = if_len,
            ip_addr_range_bottom = ip_addr_range_bottom,
            ip_addr_range_top = ip_addr_range_top,
        )

        self.ip_mode = ip_mode
        if ip_mode == 4:
            self._params['if_netmask'] = commonl.ipv4_len_to_netmask_ascii(if_len)

        if allow_unmapped:
            self._params["allow_known_clients"] = "allow known clients;"
        else:
            self._params["allow_known_clients"] = "# all clients allowed"


        self.debug = debug
        self.log = None
        self.target = None	# we find this when power_*_do() is called
        self.state_dir = None
        self.pxe_dir = None
        self.dhcpd_pidfile = None
        self.tftpd_pidfile = None

    def _dhcp_conf_write_ipv4(self, f):
        # generate the ipv4 part
        self.log.info("%s: IPv4 net/mask %s/%s",
                      self._params['if_name'], self._params['if_net'],
                      self._params['if_netmask'])
        # We only do PXE over ipv4
        f.write("""\
option space pxelinux;
option pxelinux.magic code 208 = string;
option pxelinux.configfile code 209 = text;
option pxelinux.pathprefix code 210 = text;
option pxelinux.reboottime code 211 = unsigned integer 32;
# To be used in the pxeclients class
option architecture-type code 93 = unsigned integer 16;

""")
        # FIXME: make it so using pxelinux is a configuratio template
        # (likewise on the tftp side, so we can swithc to EFI boot or
        # whatever we want)
        f.write("""\
subnet %(if_net)s netmask %(if_netmask)s {
        pool {
                %(allow_known_clients)s
                range %(ip_addr_range_bottom)s  %(ip_addr_range_top)s;
        }
        class "pxeclients" {
                match if substring (option vendor-class-identifier, 0, 9) = "PXEClient";
                # http://www.syslinux.org/wiki/index.php?title=PXELINUX#UEFI
                if option architecture-type = 00:00 {
                        filename "%(tftp_prefix)s/lpxelinux.0";
                } elsif option architecture-type = 00:09 {
                        filename "%(tftp_prefix)s/efi-x86_64/syslinux.efi";
                } elsif option architecture-type = 00:07 {
                        filename "%(tftp_prefix)s/efi-x86_64/syslinux.efi";
                } elsif option architecture-type = 00:06 {
                        filename "%(tftp_prefix)s/efi-x86/syslinux.efi";
                } else {
                        filename "%(tftp_prefix)s/lpxelinux.0";
                }
                # Point to the TFTP server, which is the same as this
                next-server %(if_addr)s;
        }
""" % self._params)

        # Now, enumerate the targets that are in this local
        # configuration and figure out what's their IP address in
        # this network; create a hardcoded entry for them.
        #
        # FIXME: This leaves a gap, as targets in other servers could
        # be connected to this network. Sigh.
        for target_id, target in ttbl.config.targets.iteritems():
            interconnects = target.tags.get('interconnects', {})
            for ic_id, interconnect in interconnects.iteritems():
                if ic_id != self.target.id:
                    continue
                mac_addr = interconnect.get('mac_addr', None)
                ipv4_addr = interconnect.get('ipv4_addr', None)
                if ipv4_addr and mac_addr:
                    f.write("""\
        host %s {
                hardware ethernet %s;
                fixed-address %s;
                option host-name "%s";
        }
""" % (target_id, mac_addr, ipv4_addr, target_id))
        f.write("""\
}
""")


    def _dhcp_conf_write_ipv6(self, f):
        # generate the ipv6 part -- we only use it to assign
        # addresses; PXE is done only over ipv4
        self.log.info("%(if_name)s: IPv6 net/len %(if_addr)s/%(if_len)s" %
                      self._params)
        f.write("""\
# This one line must be outside any bracketed scope
option architecture-type code 93 = unsigned integer 16;

subnet6 %(if_net)s/%(if_len)s {
        range6 %(ip_addr_range_bottom)s  %(ip_addr_range_top)s;

        class "pxeclients" {
                match if substring (option vendor-class-identifier, 0, 9) = "PXEClient";
                # http://www.syslinux.org/wiki/index.php?title=PXELINUX#UEFI
                if option architecture-type = 00:00 {
                        filename "%(tftp_prefix)s/lpxelinux.0";
                } elsif option architecture-type = 00:09 {
                        filename "%(tftp_prefix)s/efi-x86_64/syslinux.efi";
                } elsif option architecture-type = 00:07 {
                        filename "%(tftp_prefix)s/efi-x86_64/syslinux.efi";
                } elsif option architecture-type = 00:06 {
                        filename "%(tftp_prefix)s/efi-x86/syslinux.efi";
                } else {
                        filename "%(tftp_prefix)s/lpxelinux.0";
                }
                # Point to the TFTP server, which is the same as this
#                next-server %(if_addr)s;
        }
""" % self._params)

        # Now, enumerate the targets that are in this local
        # configuration and figure out what's their IP address in
        # this network; create a hardcoded entry for them.
        #
        # FIXME: This leaves a gap, as targets in other servers could
        # be connected to this network. Sigh.
        for target_id, target in ttbl.config.targets.iteritems():
            self.target.log.error("DEBUG checking %s", target_id)
            interconnects = target.tags.get('interconnects', {})
            for ic_id, interconnect in interconnects.iteritems():
                self.target.log.error("DEBUG checking ic %s", ic_id)
                if ic_id != self.target.id:
                    continue
                mac_addr = interconnect.get('mac_addr', None)
                ipv6_addr = interconnect.get('ipv6_addr', None)
                if ipv6_addr and mac_addr:
                    f.write("""\
        host %s {
                hardware ethernet %s;
                fixed-address6 %s;
                option host-name "%s";
        }
""" % (target_id, mac_addr, ipv6_addr, target_id))

        f.write("""\
}
""")

    def _dhcp_conf_write(self):
        # Write DHCPD configuration
        with open(os.path.join(self.state_dir, "dhcpd.conf"),
                  "wb") as f:
            if self.ip_mode == 4:
                self._dhcp_conf_write_ipv4(f)
            else:
                self._dhcp_conf_write_ipv6(f)

    def _dhcpd_start(self):
        # Fire up the daemons
        dhcpd_leases_name = os.path.join(self.state_dir, "dhcpd.leases")
        # Create the leases file if it doesn't exist
        with open(dhcpd_leases_name, 'a'):
            # touch the access/modify time to now
            os.utime(dhcpd_leases_name, None)
        if self.ip_mode == 4:
            ip_mode = "-4"
        else:
            ip_mode = "-6"
        args = [
            # Requires CAP_NET_BIND_SERVICE CAP_NET_ADMIN
            #"strace", "-f", "-s2048", "-o/tmp/kk.log",
            "dhcpd", "-d", "-q",
            # Run it in foreground, so the process group owns it and
            # kills it when exiting
            "-f",
            ip_mode,
            "-cf", os.path.join(self.state_dir, "dhcpd.conf"),
            "-lf", dhcpd_leases_name,
            "-pf", self.dhcpd_pidfile,
            self._params['if_name'],
        ]
        logfile_name = os.path.join(self.state_dir, "dhcpd.log")
        so = open(logfile_name, "wb")
        try:
            subprocess.Popen(args, shell = False, cwd = self.state_dir,
                             close_fds = True,
                             stdout = so, stderr = subprocess.STDOUT)
        except OSError as e:
            raise self.dhcpd_start_e("DHCPD failed to start: %s", e)
        pid = commonl.process_started(
            self.dhcpd_pidfile, self.dhcpd_path,
            verification_f = os.path.exists,
            verification_f_args = (self.dhcpd_pidfile,),
            tag = "dhcpd", log = self.log)
        # systemd might complain with
        #
        # Supervising process PID which is not our child. We'll most
        # likely not notice when it exits.
        #
        # Can be ignored
        if pid == None:
            raise self.dhcpd_start_e("dhcpd failed to start")
        ttbl.daemon_pid_add(pid)	# FIXME: race condition if it died?


    def _init_for_process(self, target):
        # These are the entry points we always need to initialize, we
        # might be in a different process
        if self.log == None:
            self.log = target.log
            self.state_dir = os.path.join(target.state_dir,
                                          "dhcpd-%d" % self.ip_mode)
            self.pxe_dir = os.path.join(tftp_dir, tftp_prefix)
            self.dhcpd_pidfile = os.path.join(self.state_dir, "dhcpd.pid")


    def power_on_do(self, target):
        """
        Start DHCPd and TFTPd servers on the network interface
        described by `target`
        """
        if self.target == None:
            self.target = target
        else:
            assert self.target == target
        # FIXME: detect @target is an ipv4 capable network, fail otherwise
        self._init_for_process(target)
        # Create runtime directory where we place everything
        shutil.rmtree(self.state_dir, ignore_errors = True)
        os.makedirs(self.state_dir)
        # TFTP setup
        shutil.rmtree(os.path.join(self.pxe_dir, "pxelinux.cfg"), ignore_errors = True)
        os.makedirs(os.path.join(self.pxe_dir, "pxelinux.cfg"))
        commonl.makedirs_p(os.path.join(self.pxe_dir, "efi-x86_64"))
        os.chmod(os.path.join(self.pxe_dir, "pxelinux.cfg"), 0o0775)
        shutil.copy(os.path.join(syslinux_path, "lpxelinux.0"), self.pxe_dir)
        shutil.copy(os.path.join(syslinux_path, "ldlinux.c32"), self.pxe_dir)
        # FIXME: Depends on package syslinux-efi64
        subprocess.call([ "rsync", "-a", "--delete",
                          # add that postfix / to make sure we sync
                          # the dir and not create another subdir
                          os.path.join(syslinux_path, "efi64") + "/.",
                          os.path.join(self.pxe_dir, "efi-x86_64") ])
        # We use always the same configurations; because the rsync
        # above will remove the symlink, we re-create it
        # We use a relative symlink so in.tftpd doesn't nix it
        os.symlink("../pxelinux.cfg",
                   os.path.join(self.pxe_dir, "efi-x86_64", "pxelinux.cfg"))

        # We set the parameters in a dictionary so we can use it to
        # format strings
        # FIXME: FUGLY
        self._params['if_name'] = "b" + target.id

        # FIXME: if we get the parameters from the network here, we
        # have target -- so we don't need to set them on init
        self._dhcp_conf_write()

        # FIXME: before start, filter out leases file, anything in the
        # leases dhcpd.leases file that has a "binding state active"
        # shall be kept ONLY if we still have that client in the
        # configuration...or sth like that.
        # FIXME: rm old leases file, overwrite with filtered one

        self._dhcpd_start()

    def power_off_do(self, target):
        if self.target == None:
            self.target = target
        else:
            assert self.target == target
        self._init_for_process(target)
        commonl.process_terminate(self.dhcpd_pidfile,
                                  path = self.dhcpd_path, tag = "dhcpd")

    def power_get_do(self, target):
        if self.target == None:
            self.target = target
        else:
            assert self.target == target
        self._init_for_process(target)
        dhcpd_pid = commonl.process_alive(self.dhcpd_pidfile, self.dhcpd_path)
        if dhcpd_pid != None:
            return True
        else:
            return False


def tftp_service_domain_os_power_on_pre(target, kws):
    """
    We are called before power on
    
    We will write a TFTP configuration file for the mac
    """


def power_on_pre_boot_domain_setup(target):

    # FIXME
    #
    # - tftp_boot_domain would be set as a property from the client to
    #   decide what tftp_boot_domain to boot we can also use
    #   properties to decide which vmlinuz/initrd and other boot
    #   options to set (cmdline?)
    #
    # - set in tags which interconnect is used for booting?
    #
    # - initialize keywords from interconnect, target, then properties
    #
    # - use the kws to initialize files and stuff
    #
    # - we need a name for this mechanism
    
    kws = {}
    domain = target.fsdb.get("boot_domain")
    if domain == None:
        # Not out deal, we don't know what to do, why are we here again?
        raise RuntimeError('Can\'t select domain to boot due to missing '
                           '"boot_domain" property')

    boot_ic = target.tags.get('boot_interconnect', None)
    if boot_ic == None:
        raise RuntimeError('no "boot_interconnect" tag/property defined, '
                           'can\'t boot off network')
    if not boot_ic in target.tags['interconnects']:
        raise RuntimeError('this target does not belong to the '
                           'boot interconnect "%s" defined in tag '
                           '"boot_interconnect"' % boot_ic)
    
    interconnect = target.tags['interconnects'][boot_ic]
    mac_addr = interconnect['mac_addr']

    # The service
    kws = dict(
        # FIXME: ttbd server's IP address in nwa
        # FIXME: booting over TFTP
        http_url_prefix = "http://192.168.97.1/ttbd-staging/",
        ipv4_addr = interconnect['ipv4_addr'],
        #target_ipv4_gateway = interconnect['something']
        ipv4_gateway = "192.168.97.1",	# FIXME
        # FIXME compute from addr_len
        ipv4_netmask = "255.255.255.0",
        mac_addr = interconnect['mac_addr'],
        name = target.id,
        nfs_server = "192.168.97.1",				# FIXME
        # FIXME: have the daemon hide the internal path?
        nfs_path = "/home/ttbd/images/%(boot_domain)s",
    )

    kws['extra_kopts'] = ""
    if domain == 'service':
        kws['boot_domain'] = 'tcf-live'
        kws['root_dev'] = '/dev/nfs'
        # no 'single' so it force starts getty
        # nfsroot: note we use UDP, so it is more resilitent to issues
        kws['extra_kopts'] += \
            "initrd=%(http_url_prefix)sinitramfs-%(boot_domain)s " \
            "nfsroot=%(nfs_server)s:%(nfs_path)s,udp,soft " \
            "rd.live.image selinux=0 audit=0 ro " \
            "rd.luks=0 rd.lvm=0 rd.md=0 rd.dm=0 rd.multipath=0 " \
            "plymouth.enable=0 "

        # Clearlinux
        # Can't get to boot ok
        if False:
            # - installed based on instructions /home/images/howto.rst
            kws['boot_domain'] = 'clear-24710-installer'
            # removed selinux=0 and single
            kws['extra_kopts'] = \
                "initrd=%(http_url_prefix)sinitramfs-%(boot_domain)s " \
                "root=nfs:%(nfs_server)s:%(nfs_path)s,soft " \
                "audit=0 modprobe.blacklist=ccipciedrv,aalbus,aalrms,aalrmc" \
                "init=/usr/lib/systemd/systemd-bootchart initcall_debug" \
                "tsc=reliable no_timer_check noreplace-smp" \
                "kvm-intel.nested=1 intel_iommu=igfx_off cryptomgr.notests" \
                "rcupdate.rcu_expedited=1 i915.fastboot=1 rcu_nocbs=0-64" \
                "ro rootwait"

    mac_addr = kws['mac_addr']
    file_name = os.path.join(tftp_dir, tftp_prefix, "pxelinux.cfg",
                             # FIXME: 01- is the ARP type 1 for ethernet
                             "01-" + mac_addr.replace(":", "-"))

    # note the syslinux/pxelinux format supports no long line
    # breakage, so we use Python's \ for clearer, shorter lines which
    # will be pasted all together

    if domain == "service":
        # FIXME: move somewhere else more central?
        #
        # IP specification is needed so the kernel acquires an IP address
        # and can syslog/nfsmount, etc Note we know the fields from the
        # target's configuration, as they are pre-assigned
        #
        # <client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>:<dns0-ip>:<dns1-ip>:<ntp0-ip>
        config = """\
say TCF Network boot to Service OS
#serial 0 115200
default boot
prompt 0
label boot
  # boot to %(boot_domain)s
  linux %(http_url_prefix)svmlinuz-%(boot_domain)s
  append console=tty0 console=ttyUSB0,115200 \
    ip=%(ipv4_addr)s::%(ipv4_gateway)s:%(ipv4_netmask)s:%(name)s::off:%(ipv4_gateway)s \
    root=%(root_dev)s %(extra_kopts)s
"""
    elif domain == 'elf':
        config = """\
say TCF Network boot booting ELF file
serial 0 115200
default boot
prompt 0
label boot
  kernel elf.c32
  append kernel.elf
"""
    else:
        config = """\
say TCF Network boot redirecting to local boot
serial 0 115200
default localboot
prompt 0
label localboot
  localboot 0
"""

    # FIXME:
    #
    # if there are substitution fields in the config text,
    # replace them with the keywords; repeat until there are none left
    # (as some of the keywords might bring in new substitution keys).
    #
    # Stop after ten iterations
    count = 0
    while '%(' in config:
        config = config % kws
        count += 1
        if count > 9:
            raise RuntimeError('after ten iterations could not resolve '
                               'all configuration keywords')

    with open(file_name, "w") as tf:
        tf.write(config)
        tf.flush()
        # We know the file exists, so it is safe to chmod like this
        os.chmod(tf.name, 0o644)

