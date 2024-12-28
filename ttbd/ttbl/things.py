#! /usr/bin/python3
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

"""Connect targets to other targets
--------------------------------

This module defines the interface to make targets connect to each
other and control that process.

For example, you can have a target that implements a USB disk being
connected to another via USB.

The interface to the target is the :class:`ttbl.things.interface`,
which delegates on the the different *thing* drivers
(:class:`ttbl.things.impl_c`) the implementation of the methodology to
plug or unplug the targets.
"""

import ttbl.config

class impl_c(ttbl.tt_interface_impl_c):
    """
    Define how to plug a thing (which is a target) into a target

    Each of this drivers implements the details that allows the thing
    to be plugged or unplugged from the target. For example:

    - this might be controlling a relay that connects/disconnects the
      USB lines in a cable so that it emulates a human
      connecting/disconnecting

    - this might be controlling a mechanical device which
      plugs/unplugs a cable
    """
    def __init__(self, name: str = None):
        if name == None:
            name = type(self).__name__
        ttbl.tt_interface_impl_c.__init__(self, name = name)
        self.upid_set(name)

    def target_setup(self, target, iface_name, component):
        # for each thing we added, we are going to tell them they
        # are a thing to this target, so they can unplug
        # themselves when they are released
        thing = ttbl.test_target.get(component)
        assert thing != None, \
            "%s: thing '%s' for target '%s' has to be an" \
            " existing target" % (target.id, name, target.id)
        thing.thing_to.add(target)
        publish_dict = target.tags['interfaces'][iface_name][component]['type'] = thing.type


    def plug(self, target, thing):
        """
        Plug *thing* into *target*

        Caller owns both *target* and *thing*

        :param ttbl.test_target target: target where to plug
        :param ttbl.test_target thing: thing to plug into *target*
        """
        raise NotImplementedError

    def unplug(self, target, thing):
        """
        Unplug *thing* from *target*

        Caller owns *target* (not *thing* necessarily)

        :param ttbl.test_target target: target where to unplug from
        :param ttbl.test_target thing: thing to unplug
        """
        raise NotImplementedError

    def get(self, target, thing):
        """
        :param ttbl.test_target target: target where to unplug from
        :param ttbl.test_target thing: thing to unplug

        :returns: *True* if *thing* is connected to *target*, *False*
          otherwise.
        """
        raise NotImplementedError


class interface(ttbl.tt_interface):
    """
    Define how to plug things (targets) into other targets

    A thing is a target that can be, in any form, connected to another
    target. For example, a USB device to a host, where both the US
    device and host are targets. This is so that we can make sure
    they are owned by someone before plugging, as it can alter state.

    For the specificatio of *impls* and *kwimpls*, see
    :func:`ttbl.tt_interface.impls_set`, taking into account all
    implementations need to be objects derived from
    :class:`ttbl.things.impl_c`.
    """
    def __init__(self, *impls, **kwimpls):
        ttbl.tt_interface.__init__(self)
        self.impls_set(impls, kwimpls, impl_c)

    def _target_setup(self, target, iface_name):
        pass


    def _release_hook(self, target, _force):
        # unplug all the things plugged to this target
        for name, impl in self.impls.items():
            thing = ttbl.test_target.get(name)
            if impl.get(target, thing):
                impl.unplug(target, thing)
        # if this target is a thing to other targets, unplug
        # itself from them
        for target_thing_of in target.thing_to:
            target_thing_of.things.unplug(target_thing_of, target)


    # called by the daemon when a METHOD request comes to the HTTP path
    # /ttb-vVERSION/targets/TARGET/interface/things/CALL

    def get_list(self, target, who, _args, _files, _user_path):
        data = {}
        for thing_name, impl in self.impls.items():
            thing = ttbl.test_target.get(thing_name)
            if target.target_is_owned_and_locked(who) \
               and thing.target_is_owned_and_locked(who):
                # FIXME: this is a race condition in the making, this
                # should just run and keep it acquired during the
                # operation; we need that fixed
                data[thing_name] = impl.get(target, thing)
            else:
                data[thing_name] = None
        return dict(result = data)

    def get_get(self, target, who, args, _files, _user_path):
        """
        Plug *thing* into *target*

        The user who is plugging must own this target *and* the thing.
        """
        impl, thing_name = self.arg_impl_get(args, "thing")
        thing = ttbl.test_target.get(thing_name)
        with target.target_owned_and_locked(who), \
             thing.target_owned_and_locked(who):
            return dict(result = impl.get(target, thing))
        return {}


    def put_plug(self, target, who, args, _files, _user_path):
        """
        Plug *thing* into *target*

        The user who is plugging must own this target *and* the thing.
        """
        impl, thing_name = self.arg_impl_get(args, "thing")
        thing = ttbl.test_target.get(thing_name)
        with target.target_owned_and_locked(who), \
             thing.target_owned_and_locked(who):
            if not impl.get(target, thing):
                impl.plug(target, thing)
                target.fsdb.set("interfaces.things." + thing.id + ".plugged", True)
                target.timestamp()	# If this works, it is acquired and locked
        return {}

    def put_unplug(self, target, who, args, _files, _user_path):
        """
        Unplug *thing* from *target*

        The user who is unplugging must own this target, but don't
        necessary need to own the thing.

        Note that when you release the target, all the things
        connected to it are released, even if you don't own the
        things.
        """
        impl, thing_name = self.arg_impl_get(args, "thing")
        thing = ttbl.test_target.get(thing_name)
        with target.target_owned_and_locked(who), \
             thing.target_owned_and_locked(who):
            if impl.get(target, thing):
                impl.unplug(target, thing)
                target.fsdb.set("interfaces.things." + thing.id + ".plugged", False)
                target.timestamp()	# If this works, it is acquired and locked
        return {}
