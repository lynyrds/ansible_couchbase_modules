#!/usr/bin/env python

# Written by Michael Hirschberg
#
# Change log:
# 2017-04-25: Initial commit

DOCUMENTATION = '''
---
module: cb_find_orchestrator
short_description: Find the orchestrator for a Couchbase cluster
description:
  - The M(cb_find_orchestrator) module returns the orchestrator's FQDN if found. Returns localhost if none found (fresh cluster).
author:
    - "Michael Hirschberg"
options:
  nodes:
    description:
      - List of Couchbase cluster nodes
    required: true
  user:
    description:
      - User name with sufficient rights to read configuration
    required: True
  passowrd:
    description:
      - The above user's password
    required: True
'''

EXAMPLES = '''
- cb_find_orchestrator:
    nodes:
      - node01
      - node02
      - node03
    user: admin
    password: superSecret
'''


from ansible.module_utils.basic import AnsibleModule
import requests


class CB_ORCHESTRATOR(object):
  def __init__(self, module):
    self.module = module
    self.nodes = module.params['nodes']
    self.user = module.params['user']
    self.password = module.params['password']

  def execute(self):
    my_nodes = self.nodes
    my_user = str(self.user)
    my_password = str(self.password)
    orchestrators = []

    for node in my_nodes:
      url = "http://" + node + ":8091/diag/eval"
      try:
        orchestrators.append(requests.post(url, data="node(global:whereis_name(ns_orchestrator))", auth=(my_user, my_password)).text)
      except:
        orchestrators.append("None")

    local = 0
    not_present = 0
    default = "127.0.0.1"

    for host in orchestrators:
      if default not in host and host != "None":
        orchestrator = host[6:][:-1]
        changed = False
        break
      elif host == "None":
        not_present += 1
      elif default in host:
        local += 1

    if not_present == len(orchestrators):
      return dict(failed=True, msg="Couchbase REST API is not accessible!")
    elif local == len(orchestrators):
      orchestrator = default
      changed = False
    
    return dict(chaned=changed, orchestrator=orchestrator)

def main():
  fields = dict(
    nodes=dict(required=True, type="list"),
    user=dict(required=True),
    password=dict(required=True),
  )

  module = AnsibleModule(argument_spec=fields, supports_check_mode = False)

  result = CB_ORCHESTRATOR(module).execute()

  module.exit_json(**result)


if __name__ == '__main__':
    main()
