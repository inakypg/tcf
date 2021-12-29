#! /usr/bin/python3
#
# Copyright (c) 2017-21 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Because life is as it is, this is a mess, we need this same file
# next to each setup.py file
#
#  - symlinks don't work because the bdist_rpm MANIFEST doesn't
#    dereference
#
#  - importing by manipulating the sys.path doesn't work because them
#    when packaging the toplevel setupl.py is not incldued in the
# subpackages
#
# So rules:
#
# - DO NOT EDIT THIS FILE if it is not in the root
# - edit the root/setupl.py
# - cd tcf.git; for v in $(find -mindepth 2 -iname setup.py); do cp setupl.py $(dirname $v); done
#
import glob
import os
import re
import site
import subprocess
import sys
import time

import distutils.command.install_data
import distutils.command.install_scripts
import distutils.command.install_lib

def mk_installs_py(base_dir, sysconfigdir, sharedir):
    _sysconfigdir = os.path.join(sysconfigdir, "tcf").replace("\\", "\\\\")
    _share_path = os.path.join(sharedir, "tcf").replace("\\", "\\\\")
    with open(os.path.join(base_dir, "_install.py"), "w") as f:
        f.write(f"""
#! /usr/bin/python3
#
# Copyright (c) 2021 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Note this file gets rewritten during installation
# By default, we point to the source
import os
import sys

# when running from source, we want the toplevel source dir
sysconfig_paths = [
    "{_sysconfigdir}",
]
share_path = "{_share_path}"
"""
)


def mk_version_py(base_dir, version):
    """
    Create a version.py file in a directory with whichever version
    string is passed.
    """
    with open(os.path.join(base_dir, "version.py"), "w") as f:
        f.write("""\
#! /usr/bin/python3
#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

# Generated by %s on %s
version_string = "%s"
""" % (__file__, time.asctime(), version))

def mk_windows_bat(base_dir, tcf_path):
    """
    Create a windows .bat file to allow tcf to run without using "python tcf"
    """
    with open(os.path.join(base_dir, "tcf.bat"), "w") as f:
        f.write(f"""\
@py -{sys.version_info[0]}.{sys.version_info[1]} {tcf_path}\\tcf %*
""")

def get_install_paths(
        installer,
        install, # = self.distribution.command_options.get('install', {}),
):
    if 'user' in install:
        # this means --user was given
        installer.prefix = site.getuserbase()
        sysconfigdir = os.path.join(installer.prefix, 'etc')
        sharedir = os.path.join(installer.prefix, "share")
    elif 'prefix' in install:
        # this means --prefix was given
        installer.prefix = install.get('prefix', (None, None))[1]
        if sys.platform == "win32":
            pass
        else:
            if installer.prefix == "/usr":
                sysconfigdir = "/etc"
            else:
                sysconfigdir = os.path.join(installer.prefix, 'etc')
        sharedir = os.path.join(installer.prefix, "share")
    else:
        if sys.platform == "win32":
            sysconfigdir = 'C:\\ProgramData'
            installer.prefix = 'C:\\Program Files\\'
            sharedir = os.path.join(installer.prefix, "share")
        else:
            # these have to be absolute, otherwise they will be prefixed again
            sysconfigdir = "/etc"
            sharedir = os.path.join("/usr", "share")
            installer.prefix = '/usr'

    return sysconfigdir, sharedir

# Run a post-install on installed data file replacing paths as we need
class _install_data(distutils.command.install_data.install_data):
    def run(self):
        # Workaround that install_data doesn't respect --prefix
        #
        # If prefix is given (via --user or via --prefix), then
        # extract it and add it to the paths in self.data_files;
        # otherwise, default to /usr.
        install = self.distribution.command_options.get('install', {})
        sysconfigdir, _sharedir = get_install_paths(self, install)
        new_data_files = []
        for entry in self.data_files:
            dest_path = entry[0].replace('@prefix@', self.prefix)
            dest_path = dest_path.replace('@sysconfigdir@', sysconfigdir)
            new_data_files.append((dest_path,) + entry[1:])
        self.data_files = new_data_files
        distutils.command.install_data.install_data.run(self)


# Run a post-install on installed data file replacing paths as we need
class _install_scripts(distutils.command.install_scripts.install_scripts):
    def run(self):
        install = self.distribution.command_options.get('install', {})
        # Create a .bat file for windows to run tcf without invoking python first
        if sys.platform == "win32":
            # target_dir is the scripts folder in the python installation
            target_dir = os.path.join(os.path.dirname(sys.executable),"Scripts")
            # If --user is specified, need to change path to where the script is
            if 'user' in install:
                python_version = ''.join(str(i) for i in sys.version_info[:2])
                python_folder = 'Python' + python_version
                script_dir = os.path.join(site.USER_BASE, python_folder, "Scripts")
                mk_windows_bat(target_dir, script_dir)
            else:
                mk_windows_bat(target_dir, target_dir)

        distutils.command.install_scripts.install_scripts.run(self)

class _install_lib(distutils.command.install_lib.install_lib):
    def run(self):
        # Workaround that install_data doesn't respect --prefix
        #
        # If prefix is given (via --user or via --prefix), then
        # extract it and add it to the paths in self.data_files;
        # otherwise, default to /usr/local.
        sysconfigdir, sharedir = get_install_paths(
            self,
            self.distribution.command_options.get('install', {}))
        distutils.command.install_lib.install_lib.run(self)
        # generate a new _install.py for an installed system
        mk_installs_py(
            os.path.join(self.install_dir, "tcfl"),
            sysconfigdir, sharedir)

class _install_ttbd_lib(distutils.command.install_lib.install_lib):
    def run(self):
        # Workaround that install_data doesn't respect --prefix
        #
        # If prefix is given (via --user or via --prefix), then
        # extract it and add it to the paths in self.data_files;
        # otherwise, default to /usr/local.
        sysconfigdir, sharedir = get_install_paths(
            self,
            self.distribution.command_options.get('install', {}))
        distutils.command.install_lib.install_lib.run(self)
        # generate a new _install.py for an installed system
        mk_installs_py(
            os.path.join(self.install_dir, "ttbl"),
            sysconfigdir, sharedir)

# A glob that filters symlinks
def glob_no_symlinks(pathname):
    l = []
    for file_name in glob.iglob(pathname):
        if not os.path.islink(file_name):
            l.append(file_name)
    return l


# Find which version string to settle on
version = None
try:
    import tcfl.version
    version = tcfl.version.version_string
except:
    pass

if "VERSION" in os.environ:
    version = os.environ['VERSION']
elif version:
    """ already have something """
else:
    _src = os.path.abspath(__file__)
    _srcdir = os.path.dirname(_src)
    try:
        version = subprocess.check_output(
            "git describe --tags --always --abbrev=7 --dirty".split(),
            cwd = _srcdir, stderr = subprocess.PIPE, encoding = "utf-8")
        # RPM versions can't have dash (-), so use underscores (_)
        version = version.strip().replace("-", ".")
        if re.match("^v[0-9]+.[0-9]+", version):
            version = version[1:]
    except subprocess.CalledProcessError as _e:
        print("Unable to determine %s (%s) version: %s"
              % ("tcf", _srcdir, _e.output), file = sys.stderr)
        version = "vNA"
    except OSError as e:
        # At this point, logging is still not initialized; don't
        # crash, just report a dummy version
        print("Unable to determine %s (%s) version "
              " (git not installed?): %s" % ("tcf", _srcdir, e),
              file = sys.stderr)
        version = "vNA"
