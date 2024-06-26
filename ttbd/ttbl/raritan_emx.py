#! /usr/bin/python3
#
# Copyright (c) 2019 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Original by Jing Han
#
# pylint: disable = missing-docstring

import datetime
import logging
import os
import subprocess
import urllib.parse

import commonl

import ttbl
import ttbl._install
import ttbl.power
import ttbl.capture
import raritan
import raritan.rpc
import raritan.rpc.pdumodel

class pci(ttbl.power.impl_c, ttbl.capture.impl_c): # pylint: disable = abstract-method
    r"""Power control interface for the Raritan EMX family of PDUs (eg: PX3-\*)

    Tested with a PX3-5190R with FW v3.3.10.5-43736

    In any place in the TCF server configuration where a power control
    implementation is needed and served by this PDU, thus insert:

    >>> sys.path.append("/usr/local/lib/python3.9/site-packages")
    >>> import ttbl.raritan_emx
    >>>
    >>> pc = ttbl.raritan_emx.pci('https://USER@HOSTNAME', OUTLET#,
    >>>                           password = "MYPASSOWRD")
    >>>
    >>> target.interface_add("power", ttbl.power.interface(AC = pc))

    Note this also provides an interface for capture power consumption
    measurements on units that support it.

    >>> target.interface_add("capture", ttbl.capture.interface(AC = pc))

    Power consumption can now be sampled (depending on network, about
    one sample per second)::

      $ tcf capture-start TARGETNAME AC
      $ sleep 10s
      $ tcf capture-stop-and-get TARGETNAME AC output.json

    or using the capture APIs from scripting described in
    :mod:`tcfl.target_ext_capture`.

    :param str url: URL to access the PDU in the form::

        [https://][USERNAME[:PASSWORD]@]HOSTNAME[:OUTLETNUMBER]

      Note the login credentials are optional, but must be matching
      whatever is configured in the PDU for HTTP basic
      authentication and permissions to change outlet state.

      Note that while PASSWORD can expand:

      - *FILE:FILENAME*
      - *KEYRING[:DOMAIN[:USER]]*

      due to limitation in the URL parser library, nothing in
      FILENAME, DOMAIN or USER can contain slashes, otherwise the
      parsing won't work. If that's the case, a separate password
      argument needs to be used.

      If *DOMAIN* is omitted, it is taken as *[USER@]HOSTNAME*

    :param int outlet: number of the outlet in the PDU to control;
      this is an integer 1-N (N varies depending on the PDU model)

    :param bool https_verify: (optional, default *True*) do or
      do not HTTPS certificate verification.

    :param str password: (optional) password to use for
      authentication; will be processed with
      :func:`commonl.password_get`; if not specified, it is extracted
      from the URL if present there.

    Other parameters as to :class:ttbl.power.impl_c.

    The RPC implementation is documented in
    https://help.raritan.com/json-rpc/emx/v3.4.0; while this driver
    uses the Raritan SDK driver, probably this is overkill--we could
    do the calls using JSON-RPC directly using jsonrpclib to avoid
    having to install the SDK, which is not packaged for easy
    redistribution and install.

    .. _raritan_emx_setup:

    **Bill of materials**

    - a Raritan EMX-compatible PDU (such as the PX3)

    - a network cable

    - a connection to a network switch to which the server is also
      connected (*nsN*) -- ideally this shall be an infrastructure
      network, isolated from a general use network and any test
      networks.

    **System setup**

    In the server

    1. Install the Raritan's SDK (it is not available as a PIP
       package) from https://www.raritan.com/support/product/emx
       (EMX JSON-RPC SDK)::

         $ wget http://cdn.raritan.com/download/EMX/version-3.5.0/EMX_JSON_RPC_SDK_3.5.0_45371.zip
         $ unzip -x EMX_JSON_RPC_SDK_3.5.0_45371.zip
         $ sudo install -m 0755 -o root -g root -d /usr/local/lib/python2.7/site-packages/raritan
         $ sudo cp -a emx-json-rpc-sdk-030500-45371/emx-python-api/raritan/* /usr/local/lib/python2.7/site-packages/raritan

    2. As the Raritan SDK had to be installed manually away from PIP
       or distro package management, ensurePython to looks into
       */usr/local/lib/python2.7/site-packages* for packages.

       Add your server configuration in a
       */etc/ttbd-production/conf_00_paths.py*::

         sys.path.append("/usr/local/lib/python2.7/site-packages")

       so it is parsed before any configuration that tries to import
       :mod:`ttbl.raritan_emx`.

    **Connecting the PDU**

    - Connect the PDU to the network

    - Assign the right IP and ensure name resolution works; convention
      is to use a short name *spN* (for Switch Power number *N*)

    - Configure a username/password with privilege to set the outlet
      state

    - Configure the system to power up all outlets after power loss
      (this is needed so the infrastructure can bring itself up
      without intervention, as for example it is a good practice to
      connect the servers to switched outlets so they can be remotely
      controlled).

    """
    def __init__(self, url: str, outlet_number: int = None,
                 https_verify: bool = False,
                 password: str = None, **kwargs):
        assert isinstance(url, str), \
            f"url: expected str, got {type(url)}"

        ttbl.power.impl_c.__init__(self, **kwargs)
        self.capture_program = commonl.ttbd_locate_helper(
            "raritan-power-capture.py",
            ttbl._install.share_path,
            log = logging, relsrcpath = "ttbd")
        ttbl.capture.impl_c.__init__(
            self, False, "application/json", log = "text/plain")

        self.url_base = url

        if password:
            assert isinstance(password, str), \
                f"password: expected str; got {type(password)}"
        self.password = password

        # note the indexes for the SW are 0-based, whilex in the
        # labels in the HW for humans, they are 1 based. -- we'll
        # compute that later
        if outlet_number:
            assert isinstance(outlet_number, int), \
                f"outlet_number: expected int; got {type(outlet_number)}"
            assert outlet_number >= 1, \
                f"outlet_number: expected >=1 1 int; got {outlet_number}"
        self.outlet_number = outlet_number
        self.https_verify = https_verify


        # extract the URL now for the UPID
        url, _password, outlet_number = self._url_resolve(self.url_base, password)
        url_no_password = url.scheme + "://"
        if url.username:
            url_no_password += url.username + "@"
        if self.outlet_number:
            url_no_password += f"{url.hostname}:{self.outlet_number}"
        else:
            url_no_password += f"{url.hostname}:{url.port}"

        if not password:
            password = url.password

        if not password:
            password_publish = None
        elif password.split(":", 1)[0] in ( "KEYRING", "FILE", "ENVIRONMENT" ):
            # this means the password is taken off a keyring, it is
            # safe to publish, since it is a reference to the storage place
            password_publish = password
        else:		            # this is a plain text passsword
            password_publish = "<plain-text-password-censored>"
        self.upid_set(f"Raritan PDU {url_no_password}",
                      url = url_no_password,
                      # not publishing the outlet number since it will
                      # make it confusing on how to update it - we
                      # want to update the min
                      password = password_publish)



    def target_setup(self, target, iface_name, component):
        if iface_name == "power":
            ttbl.power.impl_c.target_setup(self, target, iface_name, component)
        elif iface_name == "capture":
            ttbl.capture.impl_c.target_setup(self, target, iface_name, component)
        else:
            raise RuntimeError(
                "{target.id}: unknown interface {iface_name} for setting"
                f" up component {component}")



    def _url_resolve(self, url_base: str, password: str):
        #
        # So in here we are pulling the URL, password and outlet
        # number, from the source passed in the args; if there are no
        # source in the args, we take from self.
        #
        # This is so the code can pull defaults from the database and
        # default to config from startup. Need to run this also from
        # __init__, at which time there is no DB, so this is why this
        # fn doesn't query the DB.
        #
        # Password precendence order
        #
        # password arg
        # urb.password
        #
        # whatever is not passed in the args is taken from self
        if url_base == None:
            url_base = self.url_base
        if password == None:
            password = self.password

        # Take the URL and parse it out, defaulting password and
        # outlet number from what was configured if it doesnot come in
        # the URL
        #
        # [http://][USERNAME[:PASSWORD]]@HOSTNAME:OUTLETNUMBER
        if not "://" in url_base:
            # if there is no :// in the url, then this is missing
            # scheme and we need to add it -- this is important
            # because otherwise username:password@hostname:port will
            # be confused with username as a schema; if no schema is
            # given, default to HTTPS
            url = urllib.parse.urlparse("https://" + url_base)
        else:
            url = urllib.parse.urlparse(url_base)
        if not password and url.password:
            password = url.password
        # If there is no password specified, look in commonl.passwords
        # keyrings that allow us to set passwords by USERNAME@HOSTNAME
        if not password:
            password = commonl.password_lookup(f"{url.username}@{url.hostname}")
        if password:
            # now possibly expand passwords from the keyrings that are
            # specified as KEYRING:, FILE:, ENVIRONMENT:, etc
            password = commonl.password_get(url.netloc, url.username, password)
        if url.port:
            outlet_number = url.port
        else:
            outlet_number = self.outlet_number
        assert isinstance(outlet_number, int), \
            f"outlet_number: expected int, got {type(outlet_number)};" \
            f" needs to be defined in either *outlet_number* parameter" \
            f" or as a part of the URL (eg: http://HOSTNAME:NUMBER)"
        # outlets in the API are zero-based
        return url, password, outlet_number - 1



    def _raritan_api_handle_create(self, target: ttbl.test_target):
        try:
            # Load from the inventory the URL we have to use, so we can
            # update it real-time if we have to, or default to configuration
            password = target.fsdb.get(
                f"instrumentation.{self.upid_index}.password",
                None)
            url_base = target.fsdb.get(
                f"instrumentation.{self.upid_index}.url",
                None)
            url, password, outlet_number = self._url_resolve(url_base, password)

            # return a Raritan SDK outlet object on which we can run API
            # calls; if not initialized, initialize it on the run.
            #
            # Why not do this in __init__? Because the server runs in
            # multiple processes--this call may come from another process
            # and the initialization done in __init__ might have staled
            # when the processes forked.
            agent = raritan.rpc.Agent(
                url.scheme, url.hostname, url.username, password,
                disable_certificate_verification = not self.https_verify)
            pdu = raritan.rpc.pdumodel.Pdu("/model/pdu/0", agent)
            return pdu.getOutlets()[outlet_number]
        except Exception as e:
            target.log.error(
                f"raritan: {target.id} exception creating handle: {e}",
                exc_info = True)
            raise


    def on(self, target, _component):
        outlet_handle = self._raritan_api_handle_create(target)
        outlet_handle.setPowerState(
            raritan.rpc.pdumodel.Outlet.PowerState.PS_ON)


    def off(self, target, _component):
        outlet_handle = self._raritan_api_handle_create(target)
        outlet_handle.setPowerState(
            raritan.rpc.pdumodel.Outlet.PowerState.PS_OFF)


    def get(self, target, component):
        outlet_handle = self._raritan_api_handle_create(target)
        # We cannot call self._outlet.getState() directly--there seems
        # to be a compat issue between this version of the API in the
        # unit I tested with and what this API expects, with a missing
        # field 'loadShed' in the returned value dict.
        #
        # So we call getState by hand (from
        # raritan/Interface.py:Interface.Method) and we extract the
        # value manually.
        try:
            r = outlet_handle.getState().powerState
        except KeyError as e:
            # this happens on some PDUs (older?) where we get an exception like
            #
            ##   File "/usr/lib/python3.9/site-packages/ttbl/raritan_emx.py", line 221, in get
            ##     r = self._outlet.getState().powerState
            ##   File "/usr/lib/python3.9/site-packages/raritan/rpc/Interface.py", line 13, in __call__
            ##     return self.decode(rsp, self.parent.agent)
            ##   File "/usr/lib/python3.9/site-packages/raritan/rpc/pdumodel/__init__.py", line 3640, in decode
            ##     _ret_ = raritan.rpc.pdumodel.Outlet.State.decode(rsp['_ret_'], agent)
            ##   File "/usr/lib/python3.9/site-packages/raritan/rpc/pdumodel/__init__.py", line 3350, in decode
            ##     isLoadShed = json['isLoadShed'],
            ## KeyError: 'isLoadShed'
            obj = outlet_handle.getState
            result = obj.parent.agent.json_rpc(obj.parent.target, obj.name, {})
            r = result['_ret_']['powerState']
            if r == 0:
                # Old PDUs don't seem to use the enums in the API, so
                return False
            return True
        except raritan.rpc.HttpException as e:
            # We sometimes get network errors but
            # we don't want them to cause the whole initialziation
            # sequence to fail, so return no state.
            #
            # FIXME: retry this?
            target.log.error(f"power/{component}: network error: {e}")
            return None

        if r == raritan.rpc.pdumodel.Outlet.PowerState.PS_OFF:
            return False
        return True

    #
    # ttbl.capture.impl_c: power capture stats
    #
    def start(self, target, capturer, path):
        # Load from the inventory the URL we have to use, so we can
        # update it real-time if we have to, or default to configuration
        url_base = target.fsdb.get(
            f"instrumentation.{self.upid_index}.url",
            None)
        password = target.fsdb.get(
            f"instrumentation.{self.upid_index}.password",
            None)
        url, password, outlet_number = self._url_resolve(url_base, password)

        stream_filename = capturer + ".data.json"
        log_filename = capturer + ".capture.log"
        pidfile = "%s/capture-%s.pid" % (target.state_dir, capturer)

        logf = open(os.path.join(path, log_filename), "w+", buffering = -1)
        p = subprocess.Popen(
            [
                "stdbuf", "-e0", "-o0",
                self.capture_program,
                f"{url.scheme}://{url.username}@{url.hostname}",
                "environment",
                # the indexes the command line tool expects are
                # 1-based, whereas we stored zero based (what the API likes)
                str(outlet_number + 1),
                os.path.join(path, stream_filename),
            ],
            env = { 'RARITAN_PASSWORD': password },
            bufsize = -1,
            close_fds = True,
            shell = False,
            stderr = subprocess.STDOUT, stdout = logf.buffer,
        )

        with open(pidfile, "w+") as pidf:
            pidf.write("%s" % p.pid)
        ttbl.daemon_pid_add(p.pid)

        return True, {
            "default": stream_filename,
            "log": log_filename
        }


    def stop(self, target, capturer, path):
        pidfile = "%s/capture-%s.pid" % (target.state_dir, capturer)
        commonl.process_terminate(pidfile, tag = "capture:" + capturer,
                                  wait_to_kill = 2)

