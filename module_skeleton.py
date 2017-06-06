#!/usr/bin/env python

# Written by Michael Hirschberg
#
'''
- Plan the execution
- Document options
- Get the fields
- Get module.params
- Write check function(s)
- Write run function(s)
- Describe checks
- Describe exectution
- Test
- Document examples
'''

DOCUMENTATION = '''
---
module: MODULE_NAME
short_description: MODULE_DESCRIPTION
description:
  - The M(MODULE_NAME) can X, can't Y, should Z
author:
    - "Michael Hirschberg"
options:
  OPT1:
    description:
      - OPT1 description
    required: true
    choices: ['choice1', 'choice2']
'''

EXAMPLES = '''

- name: "Example1"
  MODULE_NAME:
    OPT1: choice1
'''


from ansible.module_utils.basic import AnsibleModule
from time import sleep
import socket
import requests
import json
import os

# Define global variables
my_fqdn = socket.getfqdn()
my_name = socket.gethostname()

class myModule(object):
  def __init__(self, module):
    self.module = module
    self.OPT1 = module.params['OPT1']

  # Write functions
  def sample_function(self):
    changed = False
    failed = False
    msg = "Boom not found, but it's ok"

    cmd = [
    'ls -l ' + self.OPT1,
    ]

    rc, stdout, stderr = self.module.run_command(cmd)

    if rc != 0:
      failed = True
      msg = "I have failed"
    else:
      if "boom" in stdout:
        changed = True
        msg = "Boom found!"

    return dict(failed=failed, changed=changed, msg=msg)


### Check functions --> ###

  def check_example(self):
    changed = True
    failed = False

    cmd = 'ls -l boom'

    rc, stdout, stderr = self.module.run_command(cmd)

    if boom in stdout:
      changed = False
    elif rc == 1:
      failed = True

    return dict(failed=failed, changed=changed)
    
### <-- Check functions ###

  def execute(self):
    if self.OPT1:
      failed,changed,msg = map(self.sample_function().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)

def main():
  fields = dict(
    # Common things
    OPT1=dict(required=True, choices=['choice1', 'choice2']),
  )

  module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

  if module.check_mode:
    if module.params['OPT1']:
      result = Couchbase(module).check_example()
      module.exit_json(**result)

  result = myModule(module).execute()

  module.exit_json(**result)

if __name__ == '__main__':
    main()
