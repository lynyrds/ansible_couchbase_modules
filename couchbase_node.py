#!/usr/bin/env python

# Change log:
# 2019-04-08: Initial commit
# 2019-06-28: Remove deprecated commands
#
# Copyright: (c) 2019, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_node is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_node is distributed in the hope that it will be useful,
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
module: couchbase_node
short_description: Manage Couchbase cluster nodes
description:
    - The M(couchbase_node) module can manage Couchbase nodes
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
    services:
        description:
            - Accepted services are data, index, query, and fts, specified as a comma-separated list
        required: false
        default: data
    nodes:
        description:
            - List of all nodes in the cluster
        required: true
    action:
        description:
            - Action to be taken for the given node
        required: true
        choices: ["join", "rejoin", "move"]
    force:
        description:
            - If a graceful failover isn't possible, enforce a hard failover
        required: false
        default: false
    recovery_type:
        description:
            - Set recovery type if re-joining a node
        required: false
        choices: ["full", "delta"]
        default: "full"
'''

EXAMPLES = '''
# nodes list is needed to reliably detect the cluster's orchestrator

- name: "Join nodes"
    couchbase_cluster:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
        action: join
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
        self.nodes = module.params['nodes']
        self.group = module.params['group']
        self.action = module.params['action']
        self.services = module.params['services']
        self.recovery_type = module.params['recovery_type']

    def join_node(self):
        changed = False
        failed = False

        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        sleep (5)

        my_services = self.services

        cmd = [
            cbcli, 'server-add',
            '-c', masters['cluster'],
            '--server-add=' + my_fqdn,
            '--server-add-username=' + self.cb_admin, '--server-add-password=' + self.admin_password,
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--services=' + my_services
        ]

        join_rc, stdout, stderr = self.module.run_command(cmd)

        my_message = stdout + stderr

        move_rc = 0

        if self.group:
            sleep(5)

            move = move_node(self)
            my_message = my_message + move['stdout'] + move['stderr']
            move_rc = move['rc']

        all_rc = move_rc + join_rc

        if all_rc != 0:
            failed = True
        else:
            changed=True

        return dict(rc=all_rc, failed=failed, changed=changed, msg=my_message)

    def rejoin_node(self):
        changed = False
        failed = False

        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        sleep (2)

        cmd = [
             cbcli, 'recovery',
             '--server-recovery=' + my_fqdn + ":" + self.admin_port,
             '--recovery-type=' + self.recovery_type,
             '-c', masters['cluster'],
             '--username=' + self.cb_admin, '--password=' + self.admin_password
        ]

        recovery_rc, stdout, stderr = self.module.run_command(cmd)
        recovery_message = stdout + stderr

        if recovery_rc != 0:
            failed = True
        else:
            changed = True


        return dict(rc=recovery_rc, failed=failed, changed=changed, msg=recovery_message)


### Check functions --> ###
    def check_node(self, my_action):
        changed = False
        failed = False
        msg = {}
        msg['join'] = "Already part of the cluster, nothing to do"
        msg['rejoin'] = "Already rejoined, nothing to do"
        msg['move'] = "Aready in the right server group, nothing to do"

        try:
            node_state = get_health(self)
            if my_action == "join" and node_state['canJoin'] == True:
                changed = True
                msg['join'] = "New node found, will join"
            if my_action == "rejoin" and node_state['canReJoin'] == True:
                changed = True
                msg['rejoin'] = "This node is going to be rejoined"
            if my_action == "move" and node_state['canEdit'] == True:
                my_group = get_my_group(self)
                if self.group != my_group:
                    msg['move'] = "Will move the node to " + self.group
        except:
            failed = True
            msg = "Failed to discover node's state"

        return dict(failed=failed, changed=changed, msg=msg[my_action])

### <-- Check functions ###

    def execute(self):
        failed = False
        changed = False
        msg = ""

        if self.action == "join":
            failed,changed,msg = map(self.check_node('join').get, ('failed','changed','msg'))
            if not failed and changed:
                failed,changed,msg = map(self.join_node().get, ('failed','changed','msg'))
        if self.action == "rejoin":
            failed,changed,msg = map(self.check_node('rejoin').get, ('failed','changed','msg'))
            if not failed and changed:
                failed,changed,msg = map(self.rejoin_node().get, ('failed','changed','msg'))

        return dict(failed=failed,changed=changed,msg=msg)

def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        group=dict(required=False),
        # Action type
        action=dict(required=True, choices=["join", "rejoin", "move"]),
        # Options
        services=dict(required=False, default="data"),
        force=dict(required=False, default=False, type="bool"),
        recovery_type=dict(required=False, default="full", choices=["full", "delta"]),
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.check_mode:
        my_mode = module.params['action']
        result = Couchbase(module).check_node(my_mode)
        module.exit_json(**result)

    result = Couchbase(module).execute()

    module.exit_json(**result)

if __name__ == '__main__':
        main()
