#! /usr/bin/python3
#
# Copyright (c) 2019-20 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Simple TAPS report driver
-------------------------

:class:`tcfl.report_taps.driver` reports in TAPS format to console output::

  ok 1 (passed) PASS/ed53lo test_name @TARGETNAMEs
  ok 2 (skipped) SKIP/dk3d test_other_name @TARGETNAMEs
  not ok 3 (failed) FAIL/3dr43 test_another_name @TARGETNAMEs

Fields are similar to the ones reported with the :mod:`console driver
<tcfl.report_console>`. See for reference.

Limitations / PENDING
^^^^^^^^^^^^^^^^^^^^^

 - can't show progress of testcase execution, as TAPS format is first
   result summary, then output.

 - currently only prints the result message, not the test output

 - it doesn't print the expected testcase count

Usage
^^^^^

In any :ref:`TCF configuration file <tcf_client_configuration>`, add::

>>> import tcfl.report_taps
>>> tcfl.report_driver_c.add(tcfl.report_taps.driver(), name = "console")

"""
import logging

import tcfl

class driver(tcfl.report_driver_c):

    def __init__(self):
        tcfl.report_driver_c.__init__(self)
        self.count = 1

    def report(self, testcase, target, tag, ts, delta,
               level, message, alevel, attachments):
        """
        Report into TAPS driver

        Note this driver only produces messages upon completion.
        """
        # Extreme chitchat we ignore it -- this is mainly the failed
        # to acquire (busy, retrying), which can add to a truckload of
        # messages
        if tag == "INFO" and level >= 6:
            return

        # this only reports the final completion status
        if not message.startswith("COMPLETION"):
            return

        # translate from TCF result to TAPS result
        tag_prefix = ""
        tag_suffix = ""
        if tag == "PASS":
            result = "ok"
        elif tag == "FAIL":
            result = "not ok"
            tag_suffix = "(failed)"
        elif tag == "ERRR":
            result = "not ok"
            tag_suffix = "(errored)"
        elif tag == "BLCK":
            result = "not ok"
            tag_suffix = "(blocked)"
        elif tag == "SKIP":
            result = "not ok"
            tag_prefix = "# skip"
        else:
            result = "not ok"

        if testcase.target_group:
            location = "@ " + testcase.target_group.name
        else:
            location = ""
        print("%s %d %s %s/%s %s %s %s\n" \
            % (result, self.count, tag_prefix, tag, testcase.ident(),
               testcase.name, location, tag_suffix))
        self.count += 1
