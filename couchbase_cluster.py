#!/usr/bin/env python

# Written by Michael Hirschberg
#
# Change log:
# 2017-04-28: Initial commit
# 2017-05-29: Add bucket creation
# 2017-05-30: Add enable LDAP
# 2017-05-31: Add create/delete user, setting autofailover
# 2017-06-01: Add enable/disable audit
# 2017-06-06: Add restrict TLS, disable UI over http

DOCUMENTATION = '''
---
module: couchbase_cluster
short_description: Manage Couchbase clusters
description:
  - The M(couchbase_cluster) module can create a Couchbase cluster, add/remove nodes, rebalance
author:
    - "Michael Hirschberg"
options:
  cb_admin:
    description:
      - Couchbase admin user
    required: true
  admin_password:
      - Couchbase admin password. Make sure you set no_log=True in your tasks!
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
  auto_failover:
    description:
      - Enable / disable auto failover (please use run_once: True in your task!)
    required: false
  auto_failover_timeout:
    description:
      - Set auto failover timeout. Minimum=5 seconds. Default=30 seconds
    required: false
    default: 30
  audit_enabled:
    description:
      - Enable or disable audit (please use run_once: True in your task!)
    required: false
  audit_log_rotate_interval:
    description:
      - Audit log rotation interval, in seconds. Default is 86400 (24 hours)
    required: false
    default: 86400
 audit_log_path:
    description:
      - Specifies the auditing log path. This should be a path to a folder where the auditing log is kept. The folder must exist on all servers in the cluster.
    required: false
    default: /opt/couchbase/var/lib/couchbase/logs
  restrict_tls:
    description:
      - Restrict TLS to 1.2  (please use run_once: True in your task!)
    required: false
  http_ui_enabled:
    description:
      - Enable or disable the GUI over http (please use run_once: True in your task!)
    required: false
  bucket_create:
    description:
      - If a bucket should be created. User run_once: True in your tasks
    required: false
    default: false
  bucket_name:
    description:
      - Bucket to be created. Mandatory if bucket_create=true.
  bucket_mem:
    description:
      - Memory assigned to the above bucket on each node, MB. Mandatory if bucket_create=true.
    required: false
  bucket_replica:
    description:
      - Amount of replica copies for the above bucket. Default is 1.
    required: False
    default: 1
    choices: [0, 1, 2, 3]
  bucket_type:
    description:
      - Optional bucket type, either couchbase or ephemeral. The default is couchbase.
    required: false
    choices: ["couchbase", "ephemeral"]
    default: "couchbase"
  ldap_enabled:
    description:
      - Enable LDAP authentication. For more information please refer to the official Couchbase documentation
    required: false
    default: false
  create_user:
    description:
      - If a user should be created. Use run_once: True in your tasks
    reqired: false
    default: false
  delete_user:
    description:
      - If a user should be deleted. Use run_once: True in your tasks
    required: false
    default: false
  user_type:
    description:
      - If the user should local or external
    required: false
    default: local
    choices: ["local", "external"]
  rbac_user_name:
    description:
      - User name to be created/deleted. Mandatory if create_user or delete_user is set to True
  rbac_user_password:
    description:
      - The RBAC user password, if user_type=local
    required: false
  rbac_roles:
    description:
      - A mandatory list of rbac user roles if creating a new user. For more information please refer to the official Couchbase documentation
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
    cluster_mem: 10240
    ldap_enabled: True
  run_once: True
  no_log: True

- name: "Join nodes"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    join: True
  no_log: True
  
- name: "Enable autofailover"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    auto_failover: True
    auto_failover_timeout: 120
  run_once: True
  no_log: True
  
- name: "Enable audit"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    audit_enabled: True
  run_once: True
  no_log: True
  
- name: "Restrict TLS"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    restrict_tls: True
  run_once: True
  no_log: True
  
- name: "Disable UI over http"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    http_ui_enabled: False
  run_once: True
  no_log: True

- name: "Rebalance"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    rebalance: True
  run_once: True
  no_log: True
  
- name: "Create bucket"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    bucket_create: true
    bucket_name: iceBucket
    bucket_mem: 1024
    bucket_replica: 2
  run_once: True
  no_log: True
  
- name: "Create user"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    bucket_create: true
    bucket_name: iceBucket
    bucket_mem: 1024
    bucket_replica: 2
  run_once: True
  no_log: True
  
- name: "Create user"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    create_user: true
    rbac_user_name: alice
    rbac_user_password: SuperSecretThePassword123
    rbac_roles:
      - ro_admin
      - replication_admin    
  run_once: True
  no_log: True
  
- name: "Delete user"
  couchbase_cluster:
    cb_admin: Administrator
    admin_password: MySuperSecretPassword
    nodes:
      - node01
      - node02
    delete_user: true
    rbac_user_name: bobby
    user_type: external
  run_once: True
  no_log: True
'''


from ansible.module_utils.basic import AnsibleModule
from time import sleep
import socket
import requests
import json
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
    self.bucket_create = module.params['bucket_create']
    self.bucket_name = module.params['bucket_name']
    self.bucket_mem = module.params['bucket_mem']
    self.bucket_replica = module.params['bucket_replica']
    self.bucket_type = module.params['bucket_type']
    self.ldap_enabled = module.params['ldap_enabled']
    self.create_user = module.params['create_user']
    self.delete_user = module.params['delete_user']
    self.user_type = module.params['user_type']
    self.rbac_user_name = module.params['rbac_user_name']
    self.rbac_user_password = module.params['rbac_user_password']
    self.rbac_roles = module.params['rbac_roles']
    self.auto_failover = module.params['auto_failover']
    self.auto_failover_timeout = module.params['auto_failover_timeout']
    self.audit_enabled = module.params['audit_enabled']
    self.audit_log_rotate_interval = module.params['audit_log_rotate_interval']
    self.audit_log_path = module.params['audit_log_path']
    self.restrict_tls = module.params['restrict_tls']
    self.http_ui_enabled = module.params['http_ui_enabled']

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
    
  def create_bucket(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    cmd = [
      cbcli, 'bucket-create', 
      '-c', masters['cluster'],
      '--bucket=' + self.bucket_name,
      '--bucket-type=' + self.bucket_type,
      '--bucket-ramsize=' + str(self.bucket_mem),
      '--bucket-replica=' + str(self.bucket_replica),      
      '--wait',      
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
    ]

    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc == 0:
      changed = True
      msg = "Bucket " + self.bucket_name + " has been created"
    else:
      failed = True
      msg = "Bucket " + self.bucket_name + " creation has failed!"
    
    return dict(failed=failed, changed=changed, msg=msg)
    
  def enable_ldap(self):
    changed = False
    rc = 0
    msg = ""
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))
    
    
    if self.ldap_enabled:
      cmd = [
        cbcli, 'setting-ldap', 
        '-c', masters['cluster'],
        '--ldap-enabled=1',
        '--username=' + self.cb_admin, '--password=' + self.admin_password,      
      ]
      rc, stdout, stderr = self.module.run_command(cmd)
      if rc == 0:
        changed = True
        msg = "LDAP enabled"
      else:
        failed = True
        msg = "LDAP was NOT enabled!"
        
    return dict(failed=failed, changed=changed, msg=msg)
 
  def createUser(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    cmd = [
      cbcli, 'user-manage', 
      '-c', masters['cluster'],
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
      '--set',
      '--rbac-username=' + self.rbac_user_name,
    ]
    
    if self.user_type == "local":
      cmd.append("--rbac-password=" + self.rbac_user_password)
      
    cmd.extend([
      '--roles=' + ','.join(self.rbac_roles),
      '--auth-domain=' + self.user_type
    ])  
    
    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc == 0:
      changed = True
      msg = msg + " User has been created."
    else:
      failed = True
      msg = msg + stderr
    
    return dict(failed=failed, changed=changed, msg=msg)
    
  def deleteUser(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    cmd = [
      cbcli, 'user-manage', 
      '-c', masters['cluster'],
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
      '--delete',
      '--rbac-username=' + self.rbac_user_name,
      '--auth-domain=' + self.user_type
    ]    
    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc == 0:
      changed = True
      msg = msg + " User has been removed."
    else:
      failed = True
      msg = msg + stderr
      
    return dict(failed=failed, changed=changed, msg=msg)

  def manage_autofailover(self):
    changed = False
    msg = ""
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))
    enabled = "0"
    enabled_text = "disabled"
    
    if self.auto_failover:
      enabled = "1"
      enabled_text = "enabled"
      
    cmd = [
      cbcli, 'setting-autofailover', 
      '-c', masters['cluster'],
      '--enable-auto-failover=' + enabled,
      '--auto-failover-timeout=' + self.auto_failover_timeout,
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
    ]
    
    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc == 0:
      changed = True
      msg = "Autofailover has been " + enabled_text
    else:
      failed = True
      msg = msg + stderr
        
    return dict(failed=failed, changed=changed, msg=msg)
    
  def manage_audit(self):
    changed = False
    msg = ""
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))
    enabled = "0"
    enabled_text = "disabled"
    
    cmd = [
      cbcli, 'setting-audit', 
      '-c', masters['cluster'],
      '--username=' + self.cb_admin, '--password=' + self.admin_password,
      '--audit-enabled=' + enabled,      
    ]

    if self.audit_enabled:
      enabled = "1"
      enabled_text = "enabled"
      cmd.extend([
      '--audit-log-rotate-interval=' + self.audit_log_rotate_interval,
      '--audit-log-path=' + self.audit_log_path,
      ])
      
    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc == 0:
      changed = True
      msg = "Audit has been " + enabled_text
    else:
      failed = True
      msg = msg + stderr
        
    return dict(failed=failed, changed=changed, msg=msg)

  def manage_tls(self):
    changed = True
    failed = False
    msg = "TLS has been restricted to "
    min_version = 'tlsv1.0'
    
    if self.restrict_tls:
      min_version = 'tlsv1.2'
      
    os.system('/usr/bin/curl -X POST -u ' + self.cb_admin + ':' + self.admin_password + ' http://127.0.0.1:8091/diag/eval -d "ns_config:set(ssl_minimum_protocol, \'' + min_version + '\')"')
    
    msg = msg + min_version
    
    return dict(failed=failed, changed=changed, msg=msg)

  def manage_http_ui(self):
    changed = False
    failed = False
    msg = "UI over http has been "
    disabled = 'true'
    disabled_text = "disabled"
    
    if self.http_ui_enabled:
      disabled = 'false'
      disabled_text = "enabled"
    
    cmd = '/usr/bin/curl -X POST -u ' + self.cb_admin + ':' + self.admin_password + ' http://127.0.0.1:8091/diag/eval -d "ns_config:set(disable_ui_over_http, ' + disabled + ')"'
    os.system(cmd)
    
    msg = msg + disabled_text
    
    return dict(failed=failed, changed=changed, msg=msg)
    
### Check functions --> ###

  def check_init(self):
    if not self.cluster_mem:
      return dict (failed = True, changed = False, msg="Please provide cluster memory quota!")

    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    if (masters['cluster'] == default) and (masters['local'] == default):
      msg = "New cluster found, will initialize..."
      changed = True

    if masters['cluster'] != default:
      msg = "Found an orchestrator node: " + masters['cluster']

    return dict(failed=failed, changed=changed, msg=msg)

  def check_join(self):
    changed = False
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))

    if masters['cluster'] != default and masters['local'] == default:
      msg = "New node found, will join..."
      changed = True

    if masters['cluster'] != default and masters['local'] != default:
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

    if rc == 1:
      if "not initialized" in stdout:
        failed = True
        msg = "Trying to rebalance on a not initialized cluster / node?"
      else:
        failed = True
        msg = "Can't verify if there is a bucket."
    else:
      msg = "At least one bucket found, should not rebalance"

    return dict(failed=failed, changed=changed, msg=msg)
    
  def check_bucket(self):
    changed = False
    failed = False
    msg = ""
    url = "http://localhost:8091/pools/default/buckets/" + self.bucket_name
    if not self.bucket_name or not self.bucket_mem:
      failed = True
      msg = "Please provide both bucket_name and bucket_mem !"
    else:
      try:
        my_bucket = requests.get(url, auth=(self.cb_admin,self.admin_password))
        if my_bucket.status_code != 200:
          changed = True
          msg = "Bucket " + self.bucket_name + " not found, will be created"
      except:
        failed = True
        msg = "Connection to the Couchbase REST API has failed!"
    
    return dict(failed=failed, changed=changed, msg=msg)
    
  def check_user(self):
    # This function is NOT verifying user's password -- because there's no way how to.
    changed = False
    failed = False
    msg = ""
    
    if self.create_user or self.delete_user:
      if not self.rbac_user_name:
        failed = True
        msg = "Please provide a user name! "
    if self.create_user:
      if self.user_type == "local" and not self.rbac_user_password:
        failed = True
        msg = msg + "Please provide RBAC password! "
      if not self.rbac_roles:
        failed = True
        msg = msg + "Please provide a roles list! "
        
    failed,masters,msg = map(self.check_new().get,('failed','orchestrators','msg'))
    
    cmd = [
      cbcli, 'user-manage', 
      '-c', masters['cluster'],
      '--list',
      '--username=' + self.cb_admin, '--password=' + self.admin_password,      
    ]
    rc, stdout, stderr = self.module.run_command(cmd)
    
    if rc != 0:
      failed = True
    elif self.create_user:
      name_ok = False
      type_ok = False
      role_ok = False
      my_roles = []
      for item in json.loads(stdout):
        if item['id'] == self.rbac_user_name:
          msg = msg + "User OK. "
          name_ok = True
          for role in item['roles']:
            if len(role) > 1:
              my_roles.append(role.values()[1] + "[" + role.values()[0] + "]")
            else:
              my_roles.append(role['role'])
          if item['domain'] == self.user_type:
            msg = msg + "User type OK. "
            type_ok = True
      if not name_ok:
        msg = msg + "User not found. "
      if not type_ok:
        msg = msg + "Wrong user type. "
      if sorted(my_roles) == sorted(self.rbac_roles):
        msg = msg + "All roles found. "
        role_ok = True
      else:
        msg = msg + "Not all roles found. "
      
      if not name_ok or not type_ok or not role_ok:
        changed = True
    elif self.delete_user:
      for item in json.loads(stdout):
        if item['id'] == self.rbac_user_name:
          msg = msg + "User will be removed. "
          changed = True
        else: 
          msg = msg + "User not found"
    
    return dict(failed=failed, changed=changed, msg=msg)
    
        
    

### <-- Check functions ###

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
      
    if self.bucket_create:
      failed,changed,msg = map(self.check_bucket().get, ('failed','changed','msg'))
      if not failed and changed:
        failed,changed,msg = map(self.create_bucket().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)
      
    if self.ldap_enabled:
      failed,changed,msg = map(self.enable_ldap().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)
      
    if self.delete_user:
      failed,changed,msg = map(self.check_user().get, ('failed','changed','msg'))
      if not failed and changed:
        failed,changed,msg = map(self.deleteUser().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=changed,msg=msg)
      
    # Because there is no way how to verify user's password, let's say it's always runs and always "changed".
    if self.create_user:
      failed,changed,msg = map(self.createUser().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=True,msg=msg)
      
    # No way to check if autofailver is set or not, so always return changed=True -- same for audit
    if self.auto_failover == True or self.auto_failover == False:
      failed,changed,msg = map(self.manage_autofailover().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=True,msg=msg)
      
    
    if self.audit_enabled == True or self.audit_enabled == False:
      failed,changed,msg = map(self.manage_audit().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=True,msg=msg)
      
    if self.restrict_tls == True or self.restrict_tls == False:
      failed,changed,msg = map(self.manage_tls().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=True,msg=msg)
      
    if self.http_ui_enabled == True or self.http_ui_enabled == False:
      failed,changed,msg = map(self.manage_http_ui().get, ('failed','changed','msg'))
      return dict(failed=failed,changed=True,msg=msg)

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
    # Buckets config
    bucket_create=dict(required=False, default=False, type="bool"),
    bucket_name=dict(required=False),
    bucket_mem=dict(required=False),
    bucket_replica=dict(required=False, default=1),    
    bucket_type=dict(required=False, default="couchbase", choices=["couchbase", "ephemeral"]),
    # RBAC config
    ldap_enabled=dict(required=False, default=False, type="bool"),
    create_user=dict(required=False, default=False, type="bool"),
    delete_user=dict(required=False, default=False, type="bool"),
    user_type=dict(required=False, default="local", choices=["local", "external"]),
    rbac_user_name=dict(required=False),
    rbac_user_password=dict(required=False),
    rbac_roles=dict(required=False, default=[], type="list"),
    # Failover config
    auto_failover=dict(required=False, type='bool'),
    auto_failover_timeout=dict(required=False, default="30"),
    # Audit config
    audit_enabled=dict(required=False, type='bool'),
    audit_log_rotate_interval=dict(required=False, default="86400"),
    audit_log_path=dict(required=False, default="/opt/couchbase/var/lib/couchbase/logs"),
    # Security hardening
    restrict_tls=dict(required=False, type='bool'),
    http_ui_enabled=dict(required=False, type='bool'),
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
      
    if module.params['bucket_create']:
      result = Couchbase(module).check_bucket()
      module.exit_json(**result)
      
    if module.params['create_user'] or module.params['delete_user']:
      result = Couchbase(module).check_user()
      module.exit_json(**result)

  result = Couchbase(module).execute()

  module.exit_json(**result)

if __name__ == '__main__':
    main()
