#! /usr/bin/python3
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import errno
import logging
import os
import random
import re
import shutil
import subprocess
import time

import ipaddress
import netifaces

import commonl
import ttbl
import ttbl.dhcp
import ttbl.pc
import ttbl.pc_ykush
import ttbl.rsync
import ttbl.socat
import ttbl.usbrly08b


class vlan_pci(ttbl.power.impl_c):
    """Power controller to implement networks on the server side.

    This allows to:

    - connect a server to a test network (NUT) to provide services
      suchs as DHCP, HTTP, network tapping, proxying between NUT and
      upstream networking, etc

    - connect virtual machines running inside virtual networks in the
      server to physical virtual networks.

    This behaves as a power control implementation that when turned:

    - on: sets up the interfaces, brings them up, start capturing

    - off: stops all the network devices, making communication impossible.

    :param str bridge_ifname: Name for the network interface in
       the server that will represent a connection to the VLAN.

       This is normally set to the target name, but if it is too
       long (more than 16 characters), it will fail. This allows to
       set it to anything else.

       >>> bridge_ifname = "nw30"

    **Configuration**

    Example configuration (see :ref:`naming networks <bp_naming_networks>`):

    >>> target = ttbl.test_target("nwa")
    >>> target.interface_add("power", ttbl.power.interface(vlan_pci()))
    >>> ttbl.config.interconnect_add(
    >>>     target,
    >>>     tags = {
    >>>         'ipv4_addr': '192.168.97.1',
    >>>         'ipv4_prefix_len': 24,
    >>>         'ipv6_addr': 'fd:99:61::1',
    >>>         'ipv6_prefix_len': 104,
    >>>         'mac_addr': '02:61:00:00:00:01:',
    >>>     })

    Now QEMU targets (for example), can declare they are part of this
    network and upon start, create a tap interface for themselves::

      $ ip tuntap add IFNAME mode tap
      $ ip link set IFNAME up master bnwa
      $ ip link set IFNAME promisc on up

    which then is given to QEMU as::

      -device virtio-net-pci,netdev=nwa,mac=MACADDR,romfile=
      -netdev tap,id=nwa,script=no,if_name=IFNAME

    (targets implemented by
    :func:`conf_00_lib_pos.target_qemu_pos_add` and
    :py:func:`conf_00_lib_mcu.target_qemu_zephyr_add` with VMs
    implement this behaviour).

    If a tag named *mac_addr* is given, containing the MAC address
    of a physical interface in the system, then it will be taken over
    as the point of connection to external targets. Connectivity from
    any virtual machine in this network will be extended to said
    network interface, effectively connecting the physical and virtual
    targets.

    .. warning:: PHYSICAL mode (mac_addr) not re-tested

    .. warning:: DISABLE Network Manager's (or any other network
                 manager) control of this interface, otherwise it will
                 interfere with it and network will not operate.

                 Follow :ref:`these steps <howto_nm_disable_control>`

    **System setup**

    - *ttbd* must be ran with CAP_NET_ADMIN so it can create network
       interfaces. For that, either add to systemd's
       ``/etc/systemd/system/ttbd@.service``::

         CapabilityBoundingSet = CAP_NET_ADMIN
         AmbientCapabilities = CAP_NET_ADMIN

      or as root, give ttbd the capability::

        # setcap cap_net_admin+pie /usr/bin/ttbd

    - *udev*'s */etc/udev/rules.d/ttbd-vlan*::

        SUBSYSTEM == "macvtap", ACTION == "add", DEVNAME == "/dev/tap*", \
            GROUP = "ttbd", MODE = "0660"

      This is needed so the tap devices can be accessed by user
      *ttbd*, which is the user that runs the daemon.

      Remember to reload *udev*'s configuration with `udevadm control
      --reload-rules`.

      This is already taken care by the RPM installation.

    **Fixture setup**

    - Select a network interface to use (it can be a USB or PCI
      interface); find out it's MAC address with *ip link show*.

    - add the tag *mac_addr* with said address to the tags of the
      target object that represents the network to which which said
      interface is to be connected; for example, for a network called
      *nwc*

      >>> target = ttbl.test_target("nwa")
      >>> target.interface_add("power", ttbl.power.interface(vlan_pci()))
      >>> ttbl.config.interconnect_add(
      >>>     target,
      >>>     tags = {
      >>>         'ipv4_addr': '192.168.97.1',
      >>>         'ipv4_prefix_len': 24,
      >>>         'ipv6_addr': 'fd:00:61::1',
      >>>         'ipv6_prefix_len': 104,
      >>>         'mac_addr': "a0:ce:c8:00:18:73",
      >>>     })

      or for an existing network (such as the configuration's default
      *nwa*):

      .. code-block:: python

         # eth dongle mac 00:e0:4c:36:40:b8 is assigned to NWA
         ttbl.test_target.get('nwa').tags_update(dict(mac_addr = '00:e0:4c:36:40:b8'))

      Furthermore, default networks *nwa*, *nwb* and *nwc* are defined
      to have a power control rail (versus an individual power
      controller), so it is possible to add another power controller
      to, for example, power on or off a network switch:

      .. code-block:: python

         ttbl.test_target.get('nwa').pc_impl.append(
             ttbl.pc.dlwps7("http://USER:PASSWORD@sp5/8"))

      This creates a power controller to switch on or off plug #8 on
      a Digital Loggers Web Power Switch named *sp5* and makes it part
      of the *nwa* power control rail. Thus, when powered on, it will
      bring the network up up and also turn on the network switch.

    - add the tag *vlan* to also be a member of an ethernet VLAN
      network (requires also a *mac_addr*):

      >>> target = ttbl.test_target("nwa")
      >>> target.interface_add("power", ttbl.power.interface(vlan_pci()))
      >>> ttbl.config.interconnect_add(
      >>>     target,
      >>>     tags = {
      >>>         'ipv4_addr': '192.168.97.1',
      >>>         'ipv4_prefix_len': 24,
      >>>         'ipv6_addr': 'fd:00:61::1',
      >>>         'ipv6_prefix_len': 104,
      >>>         'mac_addr': "a0:ce:c8:00:18:73",
      >>>         'vlan': 30,
      >>>     })

      in this case, all packets in the interface described by MAC addr
      *a0:ce:c8:00:18:73* with tag *30*.

    - lastly, for each target connected to that network, update it's
      tags to indicate it:

      .. code-block:: python

         ttbl.test_target.get('TARGETNAME-NN').tags_update(
             {
               'ipv4_addr': "192.168.10.30",
               'ipv4_prefix_len': 24,
               'ipv6_addr': "fd:00:10::30",
               'ipv6_prefix_len': 104,
             },
             ic = 'nwc')

    By convention, the server is .1, the QEMU Linux virtual machines
    are set from .2 to .10 and the QEMU Zephyr virtual machines from
    .30 to .45. Physical targets are set to start at 100.

    Note the networks for targets and infrastructure :ref:`have to be
    kept separated <separated_networks>`.

    """
    def __init__(self, bridge_ifname = None):
        if bridge_ifname != None:
            assert isinstance(bridge_ifname, str) \
                and len(bridge_ifname) <= self.IFNAMSIZ, \
                "bridge_ifname: expected string of at most" \
                f" {self.IFNAMSIZ} characters; got {type(bridge_ifname)}" \
                f" {bridge_ifname}"
            commonl.verify_str_safe(bridge_ifname,
                                    name = "network interface name")
        self.bridge_ifname = bridge_ifname
        ttbl.power.impl_c.__init__(self)


    # linux/include/if.h
    IFNAMSIZ = 16


    def _if_rename(self, target):
        if self.bridge_ifname:
            bridge_ifname = self.bridge_ifname
        else:
            bridge_ifname = target.id

        if 'mac_addr' in target.tags:
            # We do have a physical device, so we are going to first,
            # rename it to match the IC's name (so it allows targets
            # to find it to run IP commands to attach to it)
            ifname = commonl.if_find_by_mac(target.tags['mac_addr'])
            if ifname == None:
                raise ValueError("Cannot find network interface with MAC '%s'"
                                 % target.tags['mac_addr'])
            if ifname != bridge_ifname:
                subprocess.check_call("ip link set %s down" % ifname,
                                      shell = True)
                subprocess.check_call("ip link set %s name b%s"
                                      % (ifname, bridge_ifname), shell = True)



    @staticmethod
    def _get_mode(target):
        if 'vlan' in target.tags and 'mac_addr' in target.tags:
            # we are creating ethernet vlans, so we do not own the
            # device exclusively and will create new links
            return 'vlan'
        elif 'vlan' in target.tags and 'mac_addr' not in target.tags:
            raise RuntimeError("vlan ID specified without a mac_addr")
        elif 'mac_addr' in target.tags:
            # we own the device exclusively
            return 'physical'
        else:
            return 'virtual'



    def on(self, target, _component):
        if self.bridge_ifname != None:
            bridge_ifname = self.bridge_ifname
        else:
            bridge_ifname = "b" + target.id
        # Bring up the lower network interface; lower is called
        # whatever (if it is a physical device) or _bNAME; bring it
        # up, make it promiscuous
        mode = self._get_mode(target)
        if mode == 'vlan':
            vlan_id = target.property_get(
                "vlan_id",
                target.property_get("vlan"))

            # our lower is a physical device, our upper is a device
            # which till tag for eth vlan %(vlan)
            ifname = commonl.if_find_by_mac(target.tags['mac_addr'],
                                            physical = True)
            if not commonl.if_present(bridge_ifname):
                # Do create the new interface only if not already
                # created, otherwise daemons that are already running
                # will stop operating
                # This function might be being called to restablish a
                # half baked operating state.
                subprocess.check_call(
                    "/usr/sbin/ip link add"
                    f" link {ifname} name {bridge_ifname}"
                    f" type vlan id {vlan_id}",
                    #" protocol VLAN_PROTO"
                    #" reorder_hdr on|off"
                    #" gvrp on|off mvrp on|off loose_binding on|off"
                    shell = True)
                subprocess.check_call(	# bring lower up
                    f"/usr/sbin/ip link set dev {ifname} up promisc on",
                    shell = True)
        elif mode == 'physical':
            ifname = commonl.if_find_by_mac(target.tags['mac_addr'])
            subprocess.check_call(	# bring lower up
                f"/usr/sbin/ip link set dev {ifname} up promisc on",
                shell = True)
            self._if_rename(target)
        elif mode == 'virtual':
            # We create a bridge, to serve as lower
            if not commonl.if_present(bridge_ifname):
                # Do create the new interface only if not already
                # created, otherwise daemons that are already running
                # will stop operating
                # This function might be being called to restablish a
                # half baced operating state.
                commonl.if_remove_maybe(bridge_ifname)
                subprocess.check_call(
                    f"/usr/sbin/ip link add name {bridge_ifname} type bridge",
                    shell = True)
                subprocess.check_call(	# bring lower up
                    f"/usr/sbin/ip link set dev {bridge_ifname} up promisc on",
                    shell = True)
        else:
            raise AssertionError("Unknown mode %s" % mode)

        # Configure the IP addresses for the top interface
        subprocess.check_call(		# clean up existing address
            f"/usr/sbin/ip add flush dev {bridge_ifname}", shell = True)
        subprocess.check_call(		# add IPv6
            # if this fails, check Network Manager hasn't disabled ipv6
            # sysctl -a | grep disable_ipv6 must show all to 0
            "/usr/sbin/ip addr add"
            f"  {target.kws['ipv6_addr']}/{target.kws['ipv6_prefix_len']}"
            f" dev {bridge_ifname}",
            shell = True)
        subprocess.check_call(		# add IPv4
            "/usr/sbin/ip addr add"
            f"  {target.kws['ipv4_addr']}/{target.kws['ipv4_prefix_len']}"
            f"  dev {bridge_ifname}", shell = True)

        # Bring up the top interface, which sets up ther outing
        subprocess.check_call(
            f"/usr/sbin/ip link set dev {bridge_ifname} up promisc on",
            shell = True)



    def off(self, target, component):
        if self.bridge_ifname != None:
            bridge_ifname = self.bridge_ifname
        else:
            bridge_ifname = "b" + target.id
        # remove the top level device
        mode = self._get_mode(target)
        if mode == 'physical':
            # bring down the lower device
            ifname = commonl.if_find_by_mac(target.tags['mac_addr'])
            subprocess.check_call(
                # flush the IP addresses, bring it down
                f"/usr/sbin/ip add flush dev {ifname}; "
                f"/usr/sbin/ip link set dev {ifname} down promisc off",
                shell = True)
        elif mode == 'vlan':
            commonl.if_remove_maybe(bridge_ifname)
            # nothing; we killed the upper and on the lwoer, a
            # physical device we do nothing, as others might be using it
            pass
        elif mode == 'virtual':
            commonl.if_remove_maybe(bridge_ifname)
        else:
            raise AssertionError("Unknown mode %s" % mode)

        target.fsdb.set('power_state', 'off')	# FIXME: COMPAT/remove



    @staticmethod
    def _find_addr(addrs, addr):
        for i in addrs:
            if i['addr'] == addr:
                return i
        return None



    def get(self, target, _component):
        if self.bridge_ifname != None:
            bridge_ifname = self.bridge_ifname
        else:
            bridge_ifname = "b" + target.id
        # we know we have created an interface named bNWNAME, so let's
        # check it is there
        if not os.path.isdir("/sys/class/net/" + bridge_ifname):
            return False

        mode = self._get_mode(target)
        # FIXME: check bNWNAME exists and is up
        if mode == 'vlan':
            pass
        elif mode == 'physical':
            pass
        elif mode == 'virtual':
            pass
        else:
            raise AssertionError("Unknown mode %s" % mode)

        # Verify IP addresses are properly assigned
        addrs = netifaces.ifaddresses(bridge_ifname)
        if 'ipv4_addr' in target.kws:
            addrs_ipv4 = addrs.get(netifaces.AF_INET, None)
            if addrs_ipv4 == None:
                target.log.info(
                    "vlan_pci/%s: off because no ipv4 addresses are assigned"
                    % bridge_ifname)
                return False	                # IPv4 address not set
            addr = self._find_addr(addrs_ipv4, target.kws['ipv4_addr'])
            if addr == None:
                target.log.info(
                    "vlan_pci/%s: off because ipv4 address %s not assigned"
                    % (bridge_ifname, target.kws['ipv4_addr']))
                return False	                # IPv4 address mismatch
            prefixlen = ipaddress.IPv4Network(
                str('0.0.0.0/' + addr['netmask'])).prefixlen
            if prefixlen != target.kws['ipv4_prefix_len']:
                target.log.info(
                    "vlan_pci/%s: off because ipv4 prefix is %s; expected %s"
                    % (bridge_ifname, prefixlen, target.kws['ipv4_prefix_len']))
                return False	                # IPv4 prefix mismatch

        if 'ipv6_addr' in target.kws:
            addrs_ipv6 = addrs.get(netifaces.AF_INET6, None)
            if addrs_ipv6 == None:
                target.log.info(
                    "vlan_pci/%s: off because no ipv6 address is assigned"
                    % bridge_ifname)
                return False	                # IPv6 address not set
            addr = self._find_addr(addrs_ipv6, target.kws['ipv6_addr'])
            if addr == None:
                target.log.info(
                    "vlan_pci/%s: off because ipv6 address %s not assigned"
                    % (bridge_ifname, target.kws['ipv6_addr']))
                return False	                # IPv6 address mismatch
            prefixlen = ipaddress.IPv6Network(str(addr['netmask'])).prefixlen
            if prefixlen != target.kws['ipv6_prefix_len']:
                target.log.info(
                    "vlan_pci/%s: off because ipv6 prefix is %s; expected %s"
                    % (bridge_ifname, prefixlen, target.kws['ipv6_prefix_len']))
                return False	                # IPv6 prefix mismatch

        return True


# FIXME: replace tcpdump with a interconnect capture interface
# declare the property we normal users to be able to set
ttbl.test_target.properties_user.add('tcpdump')
