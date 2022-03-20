#! /usr/bin/python3
#
# Copyright (c) 2017-20 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Report data to a JSON file
--------------------------

This driver dumps all reported data with
:meth:`tcfl.reporter_c.report_data` in scripts to a JSON file.

It is structured as a top level dictionary; each domain is a top level
key and each data is a key entry in there. When the script completes
execution, the JSON file is written to
*report-[RUNID]:HASHID.data.json* on the current working directory.

For example, if the testcase:

>>> class _test(tcfl.tc_c):
>>>     def eval(self):
>>>         self.report_data("DOMAIN1", "NAMEA", 1)
>>>         self.report_data("DOMAIN1", "NAMEB", 4.3)
>>>         self.report_data("DOMAIN2", "NAMEC", "string")
>>>         self.report_data("DOMAIN2", "NAMED", 3)
>>>         self.report_data("DOMAIN2", "NAMEE", False)

would generate a json file like::

  {
      "DOMAIN1" : {
          "NAMEA": 1,
          "NAMEB": 4.3,
      },
      "DOMAIN2" : {
          "NAMEC": "string",
          "NAMED": 3,
          "NAMEE": False,
      }
  }

"""

import json
import logging

import tcfl

class driver(tcfl.report_driver_c):
    """
    Report data to a JSON file

    No configuration is needed
    """
    def __init__(self):
        tcfl.report_driver_c.__init__(self)
        self.docs = {}


    def report(self, testcase, target, tag, ts, delta,
               level, message, alevel, attachments):
        if testcase == tc.tc_global:	# not meant for the global reporter
            return
        hashid = testcase.kws.get('tc_hash', None)
        if not hashid:	            # can't do much if we don't have this
            return

        if message.startswith("COMPLETION"):
            doc = self.docs.get(hashid, None)
            if not doc:		# no data collected, shrug
                return
            with open(testcase.report_file_prefix + "data.json", "w") as f:
                json.dump(doc, f, skipkeys = True, indent = 4)
            del self.docs[hashid]
            return

        if tag != "DATA":
            return

        doc = self.docs.setdefault(hashid, dict())

        domain = attachments['domain']
        name = attachments['name']
        value = attachments['value']

        doc.setdefault(domain, {})
        doc[domain].setdefault(name, {})
        if target:
            doc[domain][name][target.fullid] = value
        else:
            doc[domain][name]["local"] = value

        # we keep running this everytime the script calls report_data;
        # however, when the script ends (COMPLETION message), it is
        # caught above and flushed to disk
        return
