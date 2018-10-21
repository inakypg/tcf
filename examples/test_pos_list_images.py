#! /usr/bin/python

import os
import re
import subprocess

import tcfl.tc
import tcfl.tl
import tcfl.pos

@tcfl.tc.interconnect("pos_rsync_server", mode = "all")
class _(tcfl.tc.tc_c):

    def eval(self, ic):
        ic.power.on()
        port = ic.tunnel.add(873, ic.kws['ipv4_addr'])	# rsync's
        rsync_host = ic.rtb.parsed_url.hostname
        rsync_port = port
        output = subprocess.check_output(
            [ 'rsync', '--port', str(rsync_port), rsync_host + '::images/' ],
            close_fds = True, stderr = subprocess.PIPE)
        # output looks like:
        # 
        # drwxrwxr-x          4,096 2018/10/19 00:41:04 .
        # drwxr-xr-x          4,096 2018/10/11 06:24:44 clear:live:25550
        # dr-xr-xr-x          4,096 2018/04/24 23:10:02 fedora:cloud-base-x86-64:28
        # drwxr-xr-x          4,096 2018/10/11 20:52:34 rtk::114
        # ...
        #
        # so we parse for 5 fields, take last
        for line in output.splitlines():
            tokens = line.split(None, 5)
            if len(tokens) != 5:
                continue
            image = tokens[4]
            if not ':' in image:
                continue
            print ic.fullid, image
