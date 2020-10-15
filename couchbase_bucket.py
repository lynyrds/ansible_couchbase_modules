#!/usr/bin/env python

# Change log:
# 2019-06-28: Initial version
# 2019-07-01: Initial commit. WARNING: not possible to change eviction policy if editing a bucket. This is a couchbase cli bug.
# 2020-09-21: Add support for 6.5.x, set the bucket compaction, prepare for bucket durability
#
# Copyright: (c) 2018, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_bucket is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_bucket is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details:
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/gpl-3.0.txt>.

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['stableinterface'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: couchbase_bicket
short_description: Manage Couchbase clusters
description:
    - The M(couchbase_bucket) module can manage couchbase buckets
author:
    - "Michael Hirschberg"
options:
    cb_admin:
        description:
            - "Couchbase admin user"
        required: true
    admin_password:
        description:
            - "Couchbase admin password. Make sure you set no_log=True in your tasks!"
        required: true
    admin_port:
        description:
            - "Couchbase admin port"
        required: false
        default: 8091
    nodes:
        description:
            - List of all nodes in the cluster
        required: true
    state:
        description:
            - Create/edit bucket with state=present, remove bucket with state=absent
        required: false
        default: present
        choices: ["present", "absent"]
    bucket_name:
        description:
            - "Bucket to be worked on."
        required: true
    bucket_mem:
        description:
            - "Memory assigned to the above bucket on each node, MB."
        required: true
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
    bucket_conflict_resolution:
        description:
            - Optional conflict resolution mechanism, either sequence or timestamp. Default is sequence.
        required: false
        choices: ["sequence", "timestamp"]
        default: "sequence"
    bucket_eviction_policy:
        description:
            - Optional bucket eviction policy. Defaults to valueOnly for couchbase buckets and nruEviction for ephemeral
        required: false
        choices: ["valueOnly", "fullEviction", "noEviction", "nruEviction"]
        default: "nruEviction"
    bucket_compresson:
        description:
            - Optional ephemeral bucket compression setting.
        default: "passive"
    bucket_ttl:
        description:
            - Optional bucket TTL in seconds.
        default: 0
    bucket_compaction:
        description:
            - Optional bucket compaction setting in %, from 2 to 100. Supported for CB >= 6.5
#    bucket_durability:
#        description:
#            - Very optional bucket durability setting. Accepted values for "ephemeral" buckets are "none" or "majority".  "none", "majority", "majorityAndPersistActive", or "persistToMajority" for "couchbase" buckets.
    bucket_enable_flush:
        description:
            - Enable/disable bucket flush. Default is 0 (disable)
        required: false
        default: "0"
        choices: ["0", "1"]
'''

EXAMPLES = '''
# nodes list is needed to reliably detect the cluster's orchestrator

- name: "Create bucket"
    couchbase_bucket:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
        bucket_name: iceBucket
        bucket_mem: 1024
        bucket_replica: 2
        bucket_type: ephemeral
        bucket_compression: passive
        bucket_ttl: 210
        bucket_enable_flush: 1
    run_once: True
    no_log: True

'''

RETURN = '''
action:
    description: if the taken action has failed or not
    returned: success
    type: string
    sample: cluster has been configured
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.couchbase_common import *
from time import sleep
import socket
import requests
import json
import os

class Couchbase(object):
    def __init__(self, module):
        self.module = module
        self.cb_admin = module.params['cb_admin']
        self.admin_password = module.params['admin_password']
        self.admin_port = module.params['admin_port']
        self.state = module.params['state']
        self.nodes = module.params['nodes']
        self.bucket_name = module.params['bucket_name']
        self.bucket_mem = module.params['bucket_mem']
        self.bucket_replica = module.params['bucket_replica']
        self.bucket_type = module.params['bucket_type']
        self.bucket_conflict_resolution = module.params['bucket_conflict_resolution']
        self.bucket_eviction_policy = module.params['bucket_eviction_policy']
        self.bucket_compression = module.params['bucket_compression']
        self.bucket_ttl = module.params['bucket_ttl']
        self.bucket_compaction = module.params['bucket_compaction']
#       self.bucket_durability = module.params['bucket_durability']
        self.bucket_enable_flush = module.params['bucket_enable_flush']

    def manage_bucket(self, action):
        changed = False
        bucket_action = ""

        if action == "create":
            bucket_action = "bucket-create"
        if action == "edit":
            bucket_action = "bucket-edit"
        if action == "remove":
            bucket_action = "bucket-delete"

        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        # Detect and set correct eviction policy. If someone is going to set a wrong eviction policy for the given bucket type, so be it.
        policy = self.bucket_eviction_policy

        # Default is nruEviction, so if bucket type is couchbase and nothing has been set, assume valueOnly
        if self.bucket_type == "couchbase" and policy == "nruEviction":
            policy = "valueOnly"

        cmd = [
            cbcli, bucket_action,
            '-c', masters['cluster'],
            '--bucket=' + self.bucket_name
        ]

        if action == "create":
            cmd.extend([
                '--bucket-type=' + self.bucket_type,
                '--conflict-resolution=' + self.bucket_conflict_resolution,
                '--bucket-eviction-policy=' + policy,
                '--wait'
        ])

        if action != "remove":
            cmd.extend([
                '--bucket-ramsize=' + str(self.bucket_mem),
                '--bucket-replica=' + str(self.bucket_replica),
                '--max-ttl=' + str(self.bucket_ttl),
                '--enable-flush=' + str(self.bucket_enable_flush)
            ])

            if self.bucket_type == "ephemeral":
                cmd.extend(['--compression-mode=' + self.bucket_compression])

        if self.bucket_compaction != "":
            cmd.extend(['--database-fragmentation-threshold-percentage=' + self.bucket_compaction])

#        if self.bucket_durability != '':
#            cmd.extend(['--durability-min-level=' + self.bucket_durability])


        cmd.extend([
            '--username=' + self.cb_admin,
            '--password=' + self.admin_password
        ])

        rc, stdout, stderr = self.module.run_command(cmd)

        msg = str(stdout) + str(stderr)

        if rc == 0:
            changed = True
        else:
            failed = True

        return dict(failed=failed, changed=changed, msg=msg)

### Check functions --> ###

    def check_bucket(self):
        changed = False
        failed = False
        action = ""
        msg = "Nothing to do"
        bucket_settings = {}
        url = "http://localhost:8091/pools/default/buckets/" + self.bucket_name
        if not self.bucket_name or not self.bucket_mem:
            failed = True
            msg = "Please provide both bucket_name and bucket_mem !"
        else:
            try:
                my_request = requests.get(url, auth=(self.cb_admin,self.admin_password))
                if my_request.status_code != 200:
                    changed = True
                    if self.state == "present":
                        msg = "Bucket " + self.bucket_name + " not found, will be created."
                        action = "create"
                        changed = True
                    else:
                        msg = "Bucket " + self.bucket_name + " not found anyway."
                        changed = False
                else:
                    if self.state == "absent":
                        msg = "Bucket " + self.bucket_name + " will be removed"
                        action = "remove"
                        changed = True
                    else:
                        action = "edit"
                        my_bucket = json.loads(my_request.text)

                        bucket_settings['mem'] = str(my_bucket['quota']['ram']/1024/1024/len(self.nodes))
                        if bucket_settings['mem'] != str(self.bucket_mem):
                            changed = True
                            msg = msg + "Memory quota will be changed. "

                        bucket_settings['replica'] = str(my_bucket['replicaNumber'])
                        if bucket_settings['replica'] != str(self.bucket_replica):
                            changed = True
                            msg = msg + "Replica count will be changed. "

                        bucket_settings['ttl'] = str(my_bucket['maxTTL'])
                        if bucket_settings['ttl'] != str(self.bucket_ttl):
                            changed = True
                            msg = msg + "Bucket TTL will be changed. "

                        bucket_settings['compression'] = my_bucket['compressionMode']
                        if bucket_settings['compression'] != self.bucket_compression:
                            changed = True
                            msg = msg + "Compression type will be changed. "

                        bucket_settings['eviction_policy'] = my_bucket['evictionPolicy']
                        if bucket_settings['eviction_policy'] != self.bucket_eviction_policy:
                            changed = True
                            msg = msg + "Eviction type will be changed. "

                        try:
                            bucket_settings['bucket_durability'] = my_bucket['durabilityMinLevel']
                            if bucket_settings['bucket_durability'] != self.bucket_durability and self.bucket_durability != "" :
                                changed = True
                                msg = msg + "Durability type will be changed. "
                        except:
                            pass

                        try: 
                            bucket_settings['bucket_compaction'] = str(my_bucket['autoCompactionSettings']['databaseFragmentationThreshold']['percentage'])
                            if (self.bucket_compaction != '' or self.bucket_compaction is not None) and (bucket_settings['bucket_compaction'] !=  self.bucket_compaction):
                                changed = True
                                msg = msg + "Compaction will be changed. "
                        except:
                            pass

            except:
                failed = True
                msg = "Connection to the Couchbase REST API has failed!"

        return dict(failed=failed, changed=changed, msg=msg, action=action)

### <-- Check functions ###

    def execute(self):
        failed,changed,msg,action = map(self.check_bucket().get, ('failed','changed','msg', 'action'))
        if not failed and changed:
            failed,changed,msg = map(self.manage_bucket(action).get, ('failed','changed','msg'))
        return dict(failed=failed,changed=changed,msg=msg)

def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        state=dict(required=False, default="present", choices=["present", "absent"]),
        # Buckets config
        bucket_name=dict(required=False),
        bucket_mem=dict(required=False),
        bucket_replica=dict(required=False, default=1),
        bucket_type=dict(required=False, default="couchbase", choices=["couchbase", "ephemeral"]),
        bucket_conflict_resolution=dict(required=False, default="sequence", choices=["sequence", "timestamp"]),
        bucket_eviction_policy=dict(required=False, default="nruEviction", choices=["valueOnly", "fullEviction", "noEviction", "nruEviction"]),
        bucket_compression=dict(required=False, default="passive", choices=["passive", "off", "active"]),
        bucket_compaction=dict(required=False, default=""),
#        bucket_durability=dict(required=False, default="", choices=["", "none", "majority", "majorityAndPersistActive", "persistToMajority"]),
        bucket_ttl=dict(required=False, default="0"),
        bucket_enable_flush=dict(required=False, default="0", choices=["0", "1"])
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.check_mode:
        result = Couchbase(module).check_bucket()
        module.exit_json(**result)

    result = Couchbase(module).execute()

    module.exit_json(**result)

if __name__ == '__main__':
        main()
