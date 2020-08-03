#!/usr/bin/env python

# Change log:
# 2018-07-12: Initial commit
# 2019-06-27: Fix typos
# 2019-07-04: Add failover for groups and disk failures
#
# Copyright: (c) 2018, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_cluster is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_cluster is distributed in the hope that it will be useful,
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
module: couchbase_cluster
short_description: Manage Couchbase clusters
description:
    - The M(couchbase_cluster) module creates a Couchbase cluster
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
    action:
        description:
            - Init or edit your cluster
        required: True
        choices: ["init", "edit"]
    cluster_name:
        description:
            - Cluster name
        required: false
        default: Cluster
    services:
        description:
            - Accepted services are data, index, query, and fts, specified as a comma-separated list
        required: false
        default: data
    index_type:
        description:
            - Index type, default (GSI) or memopt
        required: false
    db_compaction:
        description:
            - "Change compaction settings (db % fragmentation, tombstone. Please use run_once: True in your task!)"
        required: false
        default: false
    tombstone:
        description:
            - "Set the metadata purge interval in days (0.04 - 60, representing 1H - 60 days)"
        required: false
        default: 3
    nodes:
        description:
            - List of all nodes in the cluster
        required: true
    cluster_mem:
        description:
            - "Couchbase RAM quota, MB"
        required: true
    fts_mem:
        description:
            - "Full text search RAM quota, MB"
        required: false
    index_mem:
        description:
            - "Index RAM quota, MB"
        required: false
    auto_failover:
        description:
            - "Enable / disable auto failover (please use run_once: True in your task!)"
        required: false
        default: true
    auto_failover_timeout:
        description:
            - "Set auto failover timeout. Minimum=5 seconds. Default=30 seconds"
        required: false
        default: 30
    max_failovers:
        description:
            - Amount of servers that could be failed over automatically. Should be equal or less than the amount of data replicas available. Default is 1.
        required: false
        default: 1
        choices: ["1", "2". "3"]
    failover_server_groups:
        description:
            - Enable or disable server groups failover. Default is false.
        required: false
        default: false
    failover_on_data_disk_issues:
        description:
            - Failover on data disk issues. Default is true.
        required: false
        default: true
    data_disk_period:
        description:
            - The Data Service is checked every second for disk failures. If 60% of the checks during that time period report disk failures, then the node may be automatically failed over.
        required: false
        default: 120
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
        action: init
        cluster_mem: 10240
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
import json
import os

class Couchbase(object):
    def __init__(self, module):
        self.module = module
        self.cb_admin = module.params['cb_admin']
        self.admin_password = module.params['admin_password']
        self.admin_port = module.params['admin_port']
        self.nodes = module.params['nodes']
        self.action = module.params['action']
        self.cluster_name = module.params['cluster_name']
        self.cluster_mem = module.params['cluster_mem']
        self.index_mem = module.params['index_mem']
        self.index_type = module.params['index_type']
        self.fts_mem = module.params['fts_mem']
        self.services = module.params['services']
        self.group = module.params['group']
        self.db_compaction = module.params['db_compaction']
        self.tombstone = module.params['tombstone']
        self.auto_failover = module.params['auto_failover']
        self.auto_failover_timeout = module.params['auto_failover_timeout']
        self.max_failovers=module.params['max_failovers']
        self.failover_server_groups=module.params['failover_server_groups']
        self.failover_on_data_disk_issues=module.params['failover_on_data_disk_issues']
        self.data_disk_period=module.params['data_disk_period']

    def rename_first_node(self):
        # There is no return code, no nothing to be evaluated -- I just assume the node has been renamed OK
        os.system("/usr/bin/curl -X POST http://localhost:8091/node/controller/rename -d hostname=" + my_fqdn + "> /dev/null 2>&1")

    def cluster_edit(self):
        my_services = self.services
        changed = False
        failed = False
        msg = ""

        cmd = [
            cbcli, 'setting-cluster', '-c', my_fqdn,
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--cluster-ramsize=' + str(self.cluster_mem),
            '--cluster-name=' + self.cluster_name
        ]

        if self.index_mem and 'index' in my_services:
            cmd.extend(['--cluster-index-ramsize=' + str(self.index_mem)])
        elif self.fts_mem and 'fts' in my_services:
            cmd.extend(['--cluster-fts-ramsize=' + str(self.fts_mem)])

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc != 0:
            failed = True
        else:
            changed = True
        msg = stdout + stderr

        return dict(failed=failed, changed=changed, msg=msg)

    def cluster_init(self):
        failed = False
        changed = False

        self.rename_first_node()
        my_services = self.services

        cmd = [
            cbcli, 'cluster-init', '-c', my_fqdn,
            '--cluster-username=' + self.cb_admin, '--cluster-password=' + self.admin_password,
            '--cluster-ramsize=' + str(self.cluster_mem), '--services=' + my_services,
            '--cluster-name=' + self.cluster_name
        ]

        if self.index_mem:
            cmd.extend(['--cluster-index-ramsize=' + str(self.index_mem)])
        if self.index_type:
            cmd.extend(['--index-storage-setting=' + self.index_type])
        elif self.fts_mem:
            cmd.extend(['--cluster-fts-ramsize=' + str(self.fts_mem)])

        rc, stdout, stderr = self.module.run_command(cmd)

        if "ERROR" in stdout or "ERROR" in stderr:
        #if rc != 0:
            failed = True
        else:
            changed = True
        msg = str(stdout) + str(stderr)

        return dict(rc=rc, failed=failed, changed=changed, msg=msg)

    def setupCompaction(self):
        changed = False
        failed = False
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        cmd = [
            cbcli, 'setting-compaction', '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--compaction-db-percentage=' + str(self.db_compaction),
            '--enable-compaction-parallel=1', '--metadata-purge-interval=' + str(self.tombstone)
        ]

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
            msg = msg + str(stdout) + str(stderr)
        else:
            failed = True
            msg = msg + str(stdout) + str(stderr)

        return dict(failed=failed, changed=changed, msg=msg)

    def manage_autofailover(self):
        changed = False
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))
        enabled = "0"
        fail_group_enabled = "0"
        fail_on_disk_enabled = "0"

        if self.auto_failover:
            enabled = "1"
        if self.failover_server_groups:
            fail_group_enabled = "1"
        if self.failover_on_data_disk_issues:
            fail_on_disk_enabled = "1"


        cmd = [
            cbcli, 'setting-autofailover',
            '-c', masters['cluster'],
            '--enable-auto-failover=' + enabled,
            '--auto-failover-timeout=' + self.auto_failover_timeout,
            '--max-failovers=' + self.max_failovers,
            '--enable-failover-of-server-groups=' + fail_group_enabled,
            '--enable-failover-on-data-disk-issues=' + fail_on_disk_enabled,
            '--failover-data-disk-period=' + self.data_disk_period,
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
        ]

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
        else:
            failed = True
        msg = stdout + stderr

        return dict(failed=failed, changed=changed, msg=msg)

### Check functions --> ###

    def check_init(self):
        if not self.cluster_mem:
            return dict (failed = True, changed = False, msg="Please provide cluster memory quota!")

        changed = False

        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        if (masters['cluster'] == default) and (masters['local'] == default) and not failed:
            msg = "New cluster found, will initialize..."
            changed = True

        if masters['cluster'] != default:
            msg = "Found an orchestrator node: " + str(masters['cluster'])

        return dict(failed=failed, changed=changed, msg=msg)

### <-- Check functions ###

    def execute(self):
        failed,changed,msg = map(self.check_init().get, ('failed','changed','msg'))

        if self.action == ["init"] and (not failed and changed):
            failed,changed,msg = map(self.cluster_init().get, ('failed','changed','msg'))

        if self.action == ["edit"] and (not failed and not changed):
            failed,changed,msg = map(self.cluster_edit().get, ('failed','changed','msg'))

        # Always setup compaction and auto failover
        failed_compact,changed_compact,msg_compact = map(self.setupCompaction().get, ('failed','changed','msg'))
        failed_autofail,changed_autofail,msg_autofail = map(self.manage_autofailover().get, ('failed','changed','msg'))

        # Always move server to the right group, if any defined
        failed_move = False
        changed_move = False
        msg_move = " No group defined, not moving "
        if self.group:
            move = 0
            sleep (5)
            move = move_node(self)
            if move['rc'] != 0:
                failed_move = True
            else:
                changed_move = True
            msg_move = move['stdout'] + move['stderr']

        failed_all = failed and (failed_compact or failed_autofail or failed_move)
        changed_all = changed and (failed_compact or changed_autofail or changed_move)
        msg_all = msg + msg_compact + msg_autofail + msg_move

        return dict(failed=failed_all,changed=changed_all,msg=msg_all)

def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        group=dict(required=False),
        # What to do
        action=dict(required=True, type="list", choices=["init", "edit"]),
        # Cluster init
        cluster_name=dict(required=False, default="Cluster"),
        # Compaction settings
        db_compaction=dict(required=False, default="30"),
        tombstone=dict(required=False, default="3"),
        # Memory sizings
        cluster_mem=dict(required=False),
        fts_mem=dict(required=False),
        index_mem=dict(required=False),
        services=dict(required=False, default="data"),
        # Index type
        index_type=dict(required=False),
        # Failover config
        auto_failover=dict(required=False, default=True, type='bool'),
        auto_failover_timeout=dict(required=False, default="30"),
        max_failovers=dict(required=False, default="1", choices=["1", "2", "3"]),
        failover_server_groups=dict(required=False, default=False, type='bool'),
        failover_on_data_disk_issues=dict(required=False, default=True, type='bool'),
        data_disk_period=dict(required=False, default='120')
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.check_mode:
        result = Couchbase(module).check_init()

        if module.params['action'] == ['edit']:
            result['changed'] = True
            result['msg'] = "Check mode for editing cluster settings is not supported"

        module.exit_json(**result)


    result = Couchbase(module).execute()

    module.exit_json(**result)

if __name__ == '__main__':
        main()
