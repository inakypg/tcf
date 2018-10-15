#! /usr/bin/python2
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

#
# Invoke with
#
# VERSION=$(git describe) python ./setup.py bdist_rpm
#
#
import fileinput
import os

import distutils
import distutils.command.bdist_rpm
import distutils.command.install_data
import distutils.command.sdist
import distutils.command.build_py
import distutils.core
import distutils.sysconfig

import setupl

distutils.core.setup(
    name = 'ttbd-afapli',
    description = "TCF TTBD server AFAPLI extensions",
    long_description = """\
These are the extensions to the TTBD server that enable to do fast
imaging on PC-class targets via DHCP / TFTP.
""",
    version = setupl.version,
    url = None,
    author = "Inaky Perez-Gonzalez",
    author_email = "inaky.perez-gonzalez@intel.com",
    packages = [ ],
    scripts = [ ],
    data_files = [ ],
)
