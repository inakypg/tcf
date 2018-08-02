#! /usr/bin/python2
#
# FIXME: this is an experiment and it is not yet complete
#
# RPM dependencies:
#
# - tftp: set configs to dir upthere, indicate service is needed started, open firewall
#   need perms to create /var/lib/tftpboot/ttbd-staging as ttbd:nobody
# - dhcpd: service not started, we do our own config, open firewall
# - httpd: service started, figure out where to put it
# - nfs: server started, fixme how to place images?
# - syslinux: 
# - https server to serve images, it is way faster than tftp
#
# - nfs server serving images for service domain, easier than trusting
#   the local setup
#
# - will use properties as source of things needed to boot
# - set
# - QEMU not netbooting
#

import os
import pwd
import shutil
import stat
import subprocess

import commonl
import ttbl

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
                 if_netmask,
                 ip_addr_range_bottom,
                 ip_addr_range_top,
                 mac_ip_map = None,
                 allow_unmapped = False,
                 debug = False):
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
            if_netmask = if_netmask,
            ip_addr_range_bottom = ip_addr_range_bottom,
            ip_addr_range_top = ip_addr_range_top
        )
        if allow_unmapped:
            self._params["allow_known_clients"] = "allow known clients;"
        else:
            self._params["allow_known_clients"] = "# all clients allowed"


        self.debug = debug
        self.log = None
        self.state_dir = None
        self.pxe_dir = None
        self.dhcpd_pidfile = None
        self.tftpd_pidfile = None

    def _dhcp_conf_write(self):
        # Write DHCPD configuration
        with open(os.path.join(self.state_dir, "dhcpd.conf"), "wb") as f:
            f.write("""\
option space pxelinux;
option pxelinux.magic code 208 = string;
option pxelinux.configfile code 209 = text;
option pxelinux.pathprefix code 210 = text;
option pxelinux.reboottime code 211 = unsigned integer 32;
# To be used in the pxeclients class
option architecture-type code 93 = unsigned integer 16;

""")
            self.log.info("%s: IPv4 net/mask %s/%s",
                          self._params['if_name'], self._params['if_net'],
                          self._params['if_netmask'])
            # FIXME: make it so using pxelinux is a configuratio template (likewise on the tftp side, so we can swithc to EFI boot or whatever we want)
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
#                        filename "pxe/grubx64.efi";
                        filename  "boot/grub2/x86_64-efi/core.efi";
                } elsif option architecture-type = 00:07 {
#                        filename "pxe/grubx64.efi";
                        filename  "boot/grub2/x86_64-efi/core.efi";
                } elsif option architecture-type = 00:06 {
                        filename "pxe/syslinux-ia32.efi";
                } else {
                        filename "%(tftp_prefix)s/lpxelinux.0";
                }
                # Point to the TFTP server, which is the same as this
                next-server %(if_addr)s;
        }
""" % self._params)
            f.write("""\
}
""")
            for mac, mac_data in self._mac_ip_map.iteritems():
                ipv4_addr = mac_data.get('ipv4_addr', None)
                if ipv4_addr:
                    f.write("""\
host host-%s {
	hardware ethernet %s;
        fixed-address %s;
}
""" % (mac.replace(":", "-"), mac, ipv4_addr))



    def _dhcpd_start(self):
        # Fire up the daemons
        dhcpd_leases_name = os.path.join(self.state_dir, "dhcpd.leases")
        # Create the leases file if it doesn't exist
        with open(dhcpd_leases_name, 'a'):
            # touch the access/modify time to now
            os.utime(dhcpd_leases_name, None)
        args = [
            # Requires CAP_NET_BIND_SERVICE CAP_NET_ADMIN
            #"strace", "-f", "-s2048", "-o/tmp/kk.log",
            "dhcpd", "-d", "-q",
            # Run it in foreground, so the process group owns it and
            # kills it when exiting
            "-f",
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
            self.state_dir = os.path.join(target.state_dir, "dhcpd")
            self.pxe_dir = os.path.join(tftp_dir, tftp_prefix)
            self.dhcpd_pidfile = os.path.join(self.state_dir, "dhcpd.pid")
            self.tftpd_pidfile = os.path.join(self.state_dir, "tftpd.pid")


    def power_on_do(self, target):
        """
        Start DHCPd and TFTPd servers on the network interface
        described by `target`
        """
        # FIXME: detect @target is an ipv4 capable network, fail otherwise
        self._init_for_process(target)
        # Create runtime directory where we place everything
        shutil.rmtree(self.state_dir, ignore_errors = True)
        os.makedirs(self.state_dir)
        # TFTP setup
        shutil.rmtree(os.path.join(self.pxe_dir, "pxelinux.cfg"), ignore_errors = True)
        os.makedirs(os.path.join(self.pxe_dir, "pxelinux.cfg"))
        os.chmod(os.path.join(self.pxe_dir, "pxelinux.cfg"), 0o0775)
        shutil.copy(os.path.join(syslinux_path, "lpxelinux.0"), self.pxe_dir)
        shutil.copy(os.path.join(syslinux_path, "ldlinux.c32"), self.pxe_dir)

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
        self._init_for_process(target)
        commonl.process_terminate(self.dhcpd_pidfile,
                                  path = self.dhcpd_path, tag = "dhcpd")

    def power_get_do(self, target):
        self._init_for_process(target)
        dhcpd_pid = commonl.process_alive(self.dhcpd_pidfile, self.dhcpd_path)
        if dhcpd_pid != None:
            return True
        else:
            return False


def tftp_service_domain_os_power_on_pre(target):
    """
    We are called before power on
    
    We will write a TFTP configuration file for the mac
    """

    mac_addr = target.tags['interconnects']['nwa']['mac_addr']
    file_name = os.path.join(tftp_dir, tftp_prefix, "pxelinux.cfg",
                             # FIXME: 01-, where does it come from
                             "01-" + mac_addr.replace(":", "-"))

    # The service
    kws = dict(
        # FIXME: ttbd server's IP address in nwa
        #http_url_prefix = "http://192.168.97.1/~inaky/",	# FIXME: booting over TFTP
        http_url_prefix = "",
        nfs_server = "192.168.97.1",				# FIXME
        nfs_path = "/home/images/tcf-live",			# FIXME
        ipv4_addr = target.tags['interconnects']['nwa']['ipv4_addr'],
        #target_ipv4_gateway = target.tags['interconnects']['nwa']['something']
        ipv4_gateway = "192.168.97.1",	# FIXME
        # FIXME compute from addr_len
        ipv4_netmask = "255.255.255.0",
        name = target.id,
    )
    
    with open(file_name, "w") as tf:
        tf.write("""
say TCF Network boot
serial 0 115200
default boot
prompt 0
label boot
  # boot to service OS / tcf-live
  linux %(http_url_prefix)svmlinuz-tcf-live
  append initrd=%(http_url_prefix)sinitramfs-tcf-live \
console=ttyS0 console=ttyUSB0 console=tty0 \
        ip=%(ipv4_addr)s::%(ipv4_gateway)s:%(ipv4_netmask)s:%(name)s::off:%(ipv4_gateway)s \
root=/dev/nfs nfsroot=%(nfs_server)s:%(nfs_path)s \
rd.live.image selinux=0 audit=0
""" % kws)
        tf.flush()
        # We know the file exists
        os.chmod(tf.name, 0o644)

#<client-ip>:<server-ip>:<gw-ip>:<netmask>:<hostname>:<device>:<autoconf>:<dns0-ip>:<dns1-ip>:<ntp0-ip>

def power_on_pre_tftp_domain_switch(target):

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
    domain = target.fsdb.get("tftp_boot_domain")
    if domain == None:
        return

    
