# Copyright (c) 2016 Cloudbase Solutions Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

# This is only a wrapper over Linux implementations
if sys.platform != "win32":
    import ovs.daemon_unix as daemon_util
else:
    import ovs.daemon_windows as daemon_util

RESTART_EXIT_CODE = daemon_util.RESTART_EXIT_CODE


def make_pidfile_name(name):
    return daemon_util.make_pidfile_name(name)


def set_pidfile(name):
    daemon_util.set_pidfile(name)


def set_no_chdir():
    daemon_util.set_no_chdir()


def ignore_existing_pidfile():
    daemon_util.ignore_existing_pidfile()


def set_detach():
    daemon_util.set_detach()


def get_detach():
    return daemon_util.get_detach()


def set_monitor():
    daemon_util.set_monitor()


def daemonize():
    daemon_util.daemonize()


def daemonize_start():
    daemon_util.daemonize_start()


def daemonize_complete():
    daemon_util.daemonize_complete()


def usage():
    daemon_util.usage()


def read_pidfile(pidfile_name):
    return daemon_util.read_pidfile(pidfile_name)


def add_args(parser):
    daemon_util.add_args(parser)


def handle_args(args):
    daemon_util.handle_args(args)
