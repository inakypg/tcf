#! /usr/bin/python3
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Configuration API for *ttbd*
"""
import threading
import collections
import re

import ttbl
import ttbl.certs
import ttbl.store
import ttbl.tunnel

urls = []
targets = {}
targets_lock = threading.Lock()
_count = 0
# This is set by the main daemonpath when bringing up
state_path = None
upload_max_size = 16 * 1024 * 1024

#: Herds this server is a member of
#:

#: Herds are groups of servers that work together and federate; a herd
#: is a simple name (_a-zA-Z0-9). A server can be a member of more
#: than one herd.
#:
#: If declared, this gets exposed in the local target as *herds*
#: inventory in the form *HERD1[:HERD2[:HERD3[:...]]]*.
herds = set()


#: Enable (*True*) or disable SSL (*False* or *None*)
ssl_enabled = None
ssl_enabled_check_disregard = None
#: If :ref:`SSL is enabled <ssl_enabled>`, file which contains the
#: certificate
ssl_cert = None
#: If :data:`SSL is enabled <ssl_enabled>`, file which contains the
#: key
ssl_key = None
#: If :data:`SSL is enabled <ssl_enabled>`, and the :data:`ssl_key`
#: needs a password, specify it here.
#:
#: It will be processed with
#: :func:`commonl.password_get`, thus it can be
#: *FILE:/etc/ttbd-production/pwd.somefile* to read the password from
#: file */etc/ttbd-production/pwd.somefile*.
ssl_key_password = None

#: Parse defaults configuration blocks protected by::
#:
#:   if ttbl.config.defaults_enabled:
#:
#: This is done so that a sensible configuration can be shipped by
#: default that is easy to deactivate in a local configuration file.
#:
#: This is important as the default configuration includes the
#: definition for three networks (*nwa*, *nwb* and *nwc*) that if
#: spread around multiple servers will lead the clients to think they
#: are the same network but spread around multiple servers, when they
#: are in truth different networks.
defaults_enabled = True
default_networks = [ 'a', 'b' ]
#: Qemu target count start
#:
#: By default, qemu targets we create by default get
#: assigned IP addresses in the 90 range, so we have plenty of space
#: before for others
default_qemu_start = 90
default_qemu_count = 4

#: Number of processes to start
#:
#: How many servers shall be started, each being able to run a request
#: in parallel. Defaults to 20, but can be increased if HW is not
#: being very cooperative.
#:
#: (this is currently a hack, we plan to switch to a server that can
#: spawn them more dynamically).
processes = 20

#: Name of the current *ttbd* instance
#:
#: Multiple separate instances of the daemon can be started, each
#: named differently (or nothing).
instance = ""

#: Filename suffix for the current *ttbd* instance
#:
#: Per :data:`instance`, this defines the string that is appended to
#: different configuration files/paths that have to be instance
#: specific but cannot be some sort of directory. Normally this is
#: *-INSTANCE* (unless INSTANCE is empty).
instance_suffix = ""

#: Maximum length of the reason given to an allocation
reason_len_max = 128

#: Server implementation to use: gunicorn, tornado, flask
#:
#: (defaults to Tornado) Set in any serverconfiguration file:
#:
#: >>> ttbl.config.server = "gunicorn"
server = None

def _nested_list_flatten(l):
    for e in l:
        if isinstance(e, collections.abc.Iterable):
            for s in _nested_list_flatten(e):
                yield s
        else:
            yield e

# implementation of common interfaces that contain no
# state, only one instance is needed that all target can share
_iface_store = ttbl.store.interface()
_iface_certs = ttbl.certs.interface()


def target_add(target, _id = None, tags = None, target_type = None,
               acquirer = None):
    """
    Add a target to the list of managed targets

    :param ttbl.test_target target: target to add
    :param dict tags: Dictionary of tags that apply to the target (all
      tags are strings)
    :param str name: name of the target, by default taken from the target
      object

    :param str target_type: string describing type of the target; by
      default it's taken from the object's type.

    """
    assert isinstance(target, ttbl.test_target)
    if tags != None:
        assert isinstance(tags, dict)
        # FIXME: this shall be a recursive lookup?
        #for tag, value in tags.items():
        #    if not isinstance(tag, str) \
        #       or not isinstance(value, str):
        #        raise ValueError("tag '%s:%s' is not all strings"
        #                         % (tag, value))
        target.tags.update(tags)
    # FIXME: use a hash of path, type
    global _count
    global targets
    global targets_lock
    _count += 1
    if _id == None:
        if target.id == None:
            _id = "%04x" % _count
            target.id = _id
        else:
            _id = target.id
    else:
        assert isinstance(_id, str)
    if target_type != None:
        assert isinstance(target_type, str)
        target.type = target_type
    regex = re.compile("^[-a-zA-Z0-9_]+$")
    if not regex.match(_id):
        raise ValueError("target ID %s: invalid characters (valid: %s)" \
                         % (_id, regex.pattern))

    if acquirer == None:
        acquirer = ttbl.symlink_acquirer_c(target)
    target.acquirer = acquirer
    with targets_lock:
        if id in list(targets.keys()):
            raise ValueError("target ID %s already exists" % _id)
        targets[_id] = target
    target.tags.setdefault('interconnects', {})
    target.tags_update(dict(id = target.id, path = target.state_dir))
    assert isinstance(target.tags['interconnects'], dict)

    # default interfaces

    # tunneling interface; always on, since we can't make a
    # determination with the limited information we have here if the
    # target has an IP or not...and it is very cheap.
    global _iface_tunnel
    if not hasattr(target, "tunnel"):
        target.interface_add("tunnel", ttbl.tunnel.interface())
    if not hasattr(target, "store"):
        # dirty trick--some interfaces (eg: capture interfce needs the
        # store defined before adding it, so they might add it
        # manually. FIXME: right fix will be to always register this
        # upon creation
        global _iface_store
        target.interface_add("store", _iface_store)
    global _certs_store
    if not hasattr(target, "certs"):
        target.interface_add("certs", _iface_certs)


def interconnect_add(ic, _id = None, tags = None, ic_type = None,
                     acquirer = None):
    """
    Add a target interconnect

    An interconnect is just another target that offers interconnection
    services to other targets.

    :param ttbl.interconnect_c ic: interconnect to add

    :param str _id: name of the interconnect, by default taken from
      the object itself.

    :param dict _tags: Dictionary of tags that apply to the target (all
      tags are strings)

    :param str ic_type: string describing type of the interconnect; by
      default it's taken from the object's type.

    """
    target_add(ic, _id, tags = tags, target_type = ic_type,
               acquirer = acquirer)
    ic.tags['interfaces']['interconnect_c'] = { }

_authenticators = []
def add_authenticator(a):
    """
    Add an authentication methodology, eg:

    :param ttbl.authenticator_c a: authentication engine

    >>> add_authentication(ttbl.ldap_auth.ldap_user_authenticator("ldap://" ...))
    """
    assert isinstance(a, ttbl.authenticator_c)
    global _authenticators
    _authenticators.append(a)

#: Maximum time a target is idle before it is powered off (seconds)
target_max_idle = 30  # .5 min

#: Maximum time a target is idle before it is fully powered off (seconds)
#: (see :ref:`power states <ttbd_power_states>`)
target_max_idle_power_fully_off = 10 * target_max_idle

#: Maximum time an acquired target is idle before it is released (seconds)
target_owned_max_idle = 5 * 60  # 5 min

#: Time gap after which call the function to perform clean-up
cleanup_files_period = 60 # 60sec

#: Age of the file after which it will be deleted
cleanup_files_maxage = 86400 #  1day, count is in seconds, 24x60x60 sec

#: Which TCP port range we can use
#:
#: The server will take this into account when services that need port
#: allocation look for a port; this allows to open a certain range in a
#: firewall, for example.
#:
#: Note you want normally this in a range that allows ports that fit
#: in some preallocated range (eg: VNC requires >= 5900).
tcp_port_range = (1025, 65530)
