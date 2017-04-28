#!/usr/bin/env python

# Written by Michael Hirschberg
#
# Change log:
# 2017-04-28: Initial commit

DOCUMENTATION = '''
---
module: couchbase-cluster
short_description: Manage Couchbase clusters
description:
  - The M(couchbase-server) module can create a Couchbase cluster, add/remove nodes, rebalance
author:
    - "Michael Hirschberg"
options:
  cb_admin:
    description:
      - Couchbase admin user
    required: true
  admin_password:
      - Couchbase admin password
    required: true
  admin_port:
      - Couchbase admin port
    required: false
    default: 8091
  init:
    description:
      - Initialize cluster (please use run_once: True in your task!)
    required: false
    default: false
  join:
    description:
      - Join nodes to the cluster
    required: false
    default: false
  rebalance:
    description:
      - Rebalance the cluster (please use run_once: True in your task!). If a bucket exists, rebalance will be skipped. Use force: True to issue a rebalance anyway
    required: false
    default: false
  force:
    description:
      - Enforce a rebalance
    required: false
    default: false
  nodes:
    description:
      - List of all nodes in the cluster
    required: true
  cluster_mem:
    description:
      - Couchbase RAM quota, MB
    required: true
  fts_mem:
    description:
      - Full text search RAM quota, MB
    required: false
  index_mem:
    description:
      - Index RAM quota, MB
    required: false
'''

EXAMPLES = '''
# nodes list is needed to reliably detect the cluster's orchestrator

- name: "Initialize cluster"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    init: True
    cluster_mem: 1024
  run_once: True

- name: "Join nodes"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    join: True

- name: "Rebalance"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    rebalance: True
  run_once: True
'''


from ansible.module_utils.basic import AnsibleModule
from time import sleep
import socket
import requests
import os

cbcli = "/opt/couchbase/bin/couchbase-cli"
my_fqdn = socket.getfqdn()
my_name = socket.gethostname()
default = "127.0.0.1"

class Couchbase(object):
  def __init__(self, module):
    self.module = module
    self.cb_admin = module.params['cb_admin']
    self.admin_password = module.params['admin_password']
    self.admin_port = module.params['admin_port']
    self.nodes = module.params['nodes']
    self.init = module.params['init']
    self.join = module.params['join']
    self.rebalance = module.params['rebalance']
    self.force = module.params['force']
    self.cluster_mem = module.params['cluster_mem']
    self.index_mem = module.params['index_mem']
    self.fts_mem = module.params['fts_mem']
    self.services = module.params['services']
    self.group = module.params['group']

  def rename_first_node(self):
   # There is no return code, no nothing to be evaluated -- I just assume the node has been renamed OK
   os.system("/usr/bin/curl -X POST http://localhost:8091/node/controller/rename -d hostname=" + my_fqdn + "> /dev/null 2>&1")

  def check_new(self):
  # Check if it's a new cluster / node
  # Expects a full list of cluster nodes
  # Returns :
  # - failed = True | False
  # - cluster orchestrator
  # - local node's orchestrator
  # - a message
  # Fails :
  # If all nodes don't have an orchestrator
    all_orchestrators = {}
    all_local_orchestrators = {}
    orchestra = {}
    orchestrators = {}
    msg = ""
    failed = False
    port = str(self.admin_port)

    # Build a list of all orchestrators, try to authorize
    for node in self.nodes:
      url = "http://" + node + ":" + port + "/diag/eval"
      try:
        all_orchestrators[node] = requests.post(url, data="node(global:whereis_name(ns_orchestrator))", auth=(self.cb_admin,self.admin_password)).text
      except:
        failed = True

    # Build a list of all orchestrators, do not authorize
    for node in self.nodes:
      url = "http://" + node + ":" + port + "/diag/eval"
      try:
        all_local_orchestrators[node] = requests.post(url, data="node(global:whereis_name(ns_orchestrator))").text
      except:
        failed = True

    # Get cluster orchestrator
    orchestra = dict(set(all_orchestrators.items()) - set(all_local_orchestrators.items()))
    done = False

    if orchestra == {}:
      orchestrators['cluster'] = default
    else:
      orchestrators['cluster'] = orchestra.values()[0][6:][:-1]

    # Now, let's get a local one
    try:
      url = "http://" + default + ":" + port + "/diag/eval"
      my_local = requests.post(url, data="node(global:whereis_name(ns_orchestrator))").text
      if default in my_local or my_name in my_local:
        orchestrators['local'] = default
      else:
        orchestrators['local'] = orchestrators['cluster']
    except:
      failed = True

    if failed:
      msg = "Not all nodes are running couchbase-server!"    

    return dict(failed=failed, orchestrators=orchestrators, msg=msg) 

  def get_my_services(self):
    my_services = []
    if self.services:
      services = self.services

      try:
        if my_name in services['index']:
          my_services.append('index')
      except:
        pass

      try:
       if my_name in services['query']:
         my_services.append('query')
      except:
        pass

      try:
        if my_name in services['fts']:
          my_services.append('fts')
      except:
        pass
    else:
      my_services.append('data')

    return my_services

  def move_node(self):
    # Group 1 is the default group all servers are joined to. Right now it's not possible to verify the group your server is in -- json output isn't working
    # As of now (CB 5.0 April build), erros are redirected to the stdout, but rc=1 is OK if the group already exists
    # ToDo: validate sterr once it's redirected correctly
    # ToDo: once json output is working, read the group your server is in and move (or keep) it not assuming the default

    # First, create the group your server is in
    port = str(self.admin_port)
    cmd = [
      cbcli, 'group-manage', 
      '--group-name=' + self.group,
      '--create', 
      '--cluster=localhost', 
      '--username=' + self.cb_admin, '--password=' + self.admin_password
    ]
    rc, stdout, stderr = self.module.run_command(cmd)

    # Second, move the server to the above group
    cmd = cbcli + ' group-manage --move-servers=' + my_fqdn + ':' + port + ' --from-group="Group 1" --to-group=' + self.group + ' --cluster=localhost --username=' + self.cb_admin + ' --password=' + self.admin_password
    
    rc, stdout, stderr = self.module.run_command(cmd)

    return rc

  def cluster_init(self):
    self.rename_first_node()
    services = self.get_my_services()
    my_services = ','.join(services)

    cmd = [
      cbcli, 'cluster-init', '-c', my_fqdn, 
      '--cluster-username=' + self.cb_admin, '--cluster-password=' + self.admin_password, 
      '--cluster-ramsize=' + self.cluster_mem, '--services=' + my_services
    ]

    if self.index_mem:
      cmd.extend(['--cluster-index-ramsize=' + self.index_mem])
    elif self.fts_mem:
      cmd.extend(['--cluster-fts-ramsize=' + self.fts_mem])

    rc, stdout, stderr = self.module.run_command(cmd)

    init = rc
    my_message = "Cluster init has "
    if init != 0:
      my_message = my_message + " failed."
    else:
      my_message = my_message + " succeeded."

    sleep(5)

    move = 0
    if self.group:
      my_message = my_message + " Joining the group " + self.group + " has"
      move = self.move_node()
      if move != 0:
        my_message = my_message + " failed."
      else:
        my_message = my_message + " succeeded."

    failed = False
    changed = False
    my_ok = move + init

    if my_ok != 0:
      failed = True
    else:
      changed=True

    return dict(rc=my_ok, failed=failed, changed=changed, msg=my_message)
    
  def join_node(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))
    join = 0
    sleep (5)
    services = self.get_my_services()
    my_services = ','.join(services)
    
    cmd = [
      cbcli, 'server-add', 
      '-c', masters['cluster'],
      '--server-add=' + my_fqdn,
      '--server-add-username=' + self.cb_admin, '--server-add-password=' + self.admin_password,
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
      '--services=' + my_services 
    ]

    rc, stdout, stderr = self.module.run_command(cmd)

    join = rc
    my_message = "Joining node " + my_name + " has"
    if join != 0:
      my_message = my_message + " failed."
    else:
      my_message = my_message + " succeeded."

    move = 0

    if self.group:
      sleep(5)

      my_message = my_message + " Joining the group " + self.group + " has"
      move = self.move_node()
      if move != 0:
        my_message = my_message + " failed."
      else:
        my_message = my_message + " succeeded."

    failed = False
    changed = False
    my_ok = move + join

    if my_ok != 0:
      failed = True
    else:
      changed=True

    return dict(rc=my_ok, failed=failed, changed=changed, msg=my_message)

  def run_rebalance(self):
    failed = False
    changed = False

    cmd = cbcli + ' rebalance -c localhost --username=' + self.cb_admin + ' --password=' + self.admin_password

    rc, stdout, stderr = self.module.run_command(cmd)

    if rc != 0:
      failed = True
      msg = "Rebalance has failed"
    else:
      msg = "Rebalance has succeeded"
      changed = True

    return dict(failed=failed, changed=changed, msg=msg)

### Check functions ###

  def check_init(self):
    if not self.cluster_mem:
      return dict (failed = True, changed = False, msg="Please provide cluster memory quota!")

    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    if (masters['cluster'] == default) and (masters['local'] == default):
      msg = "New cluster found, will initialize..."
      changed = True
    elif masters['cluster'] != default:
      msg = "Found an orchestrator node: " + masters['cluster']

    return dict(failed=failed, changed=changed, msg=msg)

  def check_join(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    if masters['cluster'] != default and masters['local'] == default:
      msg = "New node found, will join..."
      changed = True
    elif masters['cluster'] != default and masters['local'] != default:
      msg = "The node " + my_name + " is already part of the cluster " + masters['cluster']

    return dict(failed=failed, changed=changed, msg=msg)

  def check_rebalance(self):
    # If there is a bucket, should not rebalance (return changed = False)
    # bucket-list prints errors on stdout -- I hope this is going to be fixed in the GA 5.0 build
    changed = False
    failed = False
    msg = "No buckets found, can rebalance"

    cmd = cbcli + ' bucket-list -c localhost --username=' + self.cb_admin + ' --password=' + self.admin_password

    rc, stdout, stderr = self.module.run_command(cmd)

    if stdout.strip() == "":
      changed = True
    elif rc == 1:
      if "not initialized" in stdout:
        failed = True
        msg = "Trying to rebalance on a not initialized cluster / node?"
      else:
        failed = True
        msg = "Can't verify if there is a bucket."
    else:
      msg = "At least one bucket found, should not rebalance"

    return dict(failed=failed, changed=changed, msg=msg)
    
   
  def execute(self):
    if self.init:
      failed,changed,msg = map(self.check_init().get, ('failed','changed','msg'))
      if not failed and changed:
        failed,changed,msg = map(self.cluster_init().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)

    if self.join:
      failed,changed,msg = map(self.check_join().get, ('failed','changed','msg'))
      if not failed and changed:
        failed,changed,msg = map(self.join_node().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)

    if self.rebalance:
      failed,changed,msg = map(self.check_rebalance().get, ('failed','changed','msg'))
      if (not failed and changed) or (not failed and not changed and self.force):
        failed,changed,msg = map(self.run_rebalance().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)

def main():
  fields = dict(
    # Common things
    cb_admin=dict(required=True),
    admin_password=dict(required=True),
    nodes=dict(required=True, type="list"),
    admin_port=dict(default="8091"),
    group=dict(required=False),
    # Cluster init and nodes join
    init=dict(required=False, default=False, type="bool"),
    join=dict(required=False, default=False, type="bool"),
    # Rebalance
    rebalance=dict(required=False, default=False, type="bool"),
    force=dict(required=False, default=False, type="bool"),
    # Memory sizings
    cluster_mem=dict(required=False),
    fts_mem=dict(required=False),
    index_mem=dict(required=False),
    services=dict(required=False),
  )

  module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

  if module.check_mode:
    if module.params['init']:
      result = Couchbase(module).check_init()
      module.exit_json(**result)

    if module.params['join']:
      result = Couchbase(module).check_join()
      module.exit_json(**result)

    if module.params['rebalance']:
      result = Couchbase(module).check_rebalance()
      module.exit_json(**result)

  result = Couchbase(module).execute()

  module.exit_json(**result)

if __name__ == '__main__':
    main()
