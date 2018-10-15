#! /usr/bin/python2

import os
import pwd
import shutil
import stat
import subprocess

import commonl
import ttbl
import ttbl.config

class pci(ttbl.tt_power_control_impl):

    class error_e(Exception):
        pass

    class start_e(error_e):
        pass

    socat_path = "/usr/bin/socat"

    """

    This class implements a power control unit that can forward ports
    in the server to other places in the network.

    It can be used to provide for access point in the NUTs (Network
    Under Tests) for the testcases to access, for example, external
    proxies. 

    .. warning:: this is incomplete!

       - ensure your firewalls are open as needed.

                    "/usr/bin/socat",
                    "-ly", "-lp", tunnel_id,
                    "%s-LISTEN:%d,fork,reuseaddr" % (proto, local_port),
                    "%s:%s:%s" % (proto, ip_addr, port)


    """

    def __init__(self,
                 local_port, remote_addr, remote_port,
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

    def power_on_do(self, target):
        """
        Start DHCPd and TFTPd servers on the network interface
        described by `target`
        """
        pidfile = os.path.join(target.state_dir, "socat.pid")
        lockfile = os.path.join(target.state_dir, "socat.lock")
        args = [
            "-lp", target.id + ".socat",
            "-ly",
            "-L", lockfile
        ]
        try:
            p = subprocess.Popen(args, shell = False, cwd = target.state_dir,
                             close_fds = True, stderr = subprocess.STDOUT)
            with open(pidfile, "w") as pidf:
                pidf.write("%s" % p.pid)
        except OSError as e:
            raise self.dhcpd_start_e("socat failed to start: %s", e)
        pid = commonl.process_started(
            pidfile, self.socat_path,
            verification_f = os.path.exists,
            verification_f_args = (lockfile,),
            tag = "socat", log = self.log)
        # systemd might complain with
        #
        # Supervising process PID which is not our child. We'll most
        # likely not notice when it exits.
        #
        # Can be ignored
        if pid == None:
            raise self.dhcpd_start_e("dhcpd failed to start")
        ttbl.daemon_pid_add(pid)	# FIXME: race condition if it died?

    def power_off_do(self, target):
        pidfile = os.path.join(target.state_dir, "socat.pid")
        commonl.process_terminate(pidfile, self.socat_path, tag = "socat")

    def power_get_do(self, target):
        pidfile = os.path.join(target.state_dir, "socat.pid")
        pid = commonl.process_alive(pidfile, self.socat_path)
        if pid != None:
            return True
        else:
            return False
