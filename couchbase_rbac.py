#!/usr/bin/env python

# Change log:
# 2019-07-02: Initial commit
# 2020-09-29: Add support for 6.5.x: LDAP integration
#
# Copyright: (c) 2019, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_rbac is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_rbac is distributed in the hope that it will be useful,
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
module: couchbase_rbac
short_description: Manage Couchbase Users
description:
    - The M(couchbase_rbac) module can create/change/remove  Couchbase internal/external users
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
    ldap_enabled:
        description:
            - Enable LDAP authentication. Can't be used along with 'state'
        required: false
        default: false
    ldap_hosts:
        description:
            - (couchbase 6.5.1+) The ldap hosts (IPs or DNS) to authenticate against separated by a comma
        required: false
    ldap_port:
        description:
            - (couchbase 6.5.1+) The ldap port to use
        required: false
    ldap_encryption:
        description:
            - (couchbase 6.5.1+) Security used to communicate with LDAP servers.
        required: false
        choices: ["tls", "startTLS", "none"]
        default: "none"
    ldap_user_dn_template:
        description:
            - (couchbase 6.5.1+) LDAP query to get user's DN.
    ldap_cacert_path:
        description:
            - (couchbase 6.5.1+) CA certificate to be used for server's certificate validation
        required: false
    ldap_bind_dn:
        description:
            - (couchbase 6.5.1+) The DN of a user to authenticate as to allow user search and groups synchronization.
        required: false
    ldap_bind_password:
        description:
            - (couchbase 6.5.1+) The bind user password
        required: false
    state:
        description:
            - "Create/change user with 'state: present', remove user with 'state: absent'. Use run_once: True in your tasks". Can't be used along with 'ldap_enabled'
        reqired: false
        default: present
        choices: ["present", "absent"]
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
    rbac_group_name:
        description:
            - Group name to create/delete. Mandatory if creating or deleting a_group
    rbac_group_roles:
        description:
            - A list of roles for the group creation
        required: false
    rbac_group_ldap_ref:
        description:
            - ldap mapping for the group
        required: false
'''

EXAMPLES = '''
# nodes list is needed to reliably detect the cluster's orchestrator

- name: "Create user"
    couchbase_cluster:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
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
        state: absent
        rbac_user_name: bobby
        user_type: external
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
import re

class Couchbase(object):
    def __init__(self, module):
        self.module = module
        self.cb_admin = module.params['cb_admin']
        self.admin_password = module.params['admin_password']
        self.admin_port = module.params['admin_port']
        self.nodes = module.params['nodes']
        self.ldap_enabled = module.params['ldap_enabled']
        self.ldap_hosts = module.params['ldap_hosts']
        self.ldap_port = module.params['ldap_port']
        self.ldap_encryption = module.params['ldap_encryption']
        self.ldap_user_dn_template = module.params['ldap_user_dn_template']
        self.ldap_cacert_path = module.params['ldap_cacert_path']
        self.ldap_bind_dn = module.params['ldap_bind_dn']
        self.ldap_bind_password = module.params['ldap_bind_password']
        self.rbac_group_name = module.params['rbac_group_name']
        self.rbac_group_roles = module.params['rbac_group_roles']
        self.rbac_group_ldap_ref = module.params['rbac_group_ldap_ref']
        self.state = module.params['state']
        self.user_type = module.params['user_type']
        self.rbac_user_name = module.params['rbac_user_name']
        self.rbac_user_password = module.params['rbac_user_password']
        self.rbac_roles = module.params['rbac_roles']

    def enable_ldap(self):
        changed = False
        rc = 0
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))


        if self.ldap_enabled:
            cmd = [
                cbcli, 'setting-ldap',
                '-c', masters['cluster'],
                '--username=' + self.cb_admin, '--password=' + self.admin_password,
            ]

            node_state = get_health(self)
            if cb_version_split <= node_state['version']:
                cmd.extend(['--authentication-enabled=1', '--authorization-enabled=1'])

                if self.ldap_hosts and self.ldap_port:
                    cmd.extend(['--hosts', self.ldap_hosts,
                                '--port', self.ldap_port])

                if self.ldap_encryption:
                    cmd.extend(['--encryption', self.ldap_encryption])

                if self.ldap_cacert_path:
                    cmd.extend(['--ldap-cacert', self.ldap_cacert_path])
                else: # if we didn't provide a CACERT path we disable certificate validation
                     cmd.extend(['--server-cert-validation=0'])

                if self.ldap_bind_dn:
                    cmd.extend(['--bind-dn', self.ldap_bind_dn])
                if self.ldap_bind_password:
                    cmd.extend(['--bind-password', self.ldap_bind_password])
                if self.ldap_user_dn_template:
                    cmd.extend(['--user-dn-template', self.ldap_user_dn_template])
            else:
                cmd.extend(['--ldap-enabled=1'])

            rc, stdout, stderr = self.module.run_command(cmd)
            if rc == 0:
                changed = True
            else:
                failed = True

            msg = stdout + stderr
        return dict(failed=failed, changed=changed, msg=msg)

    def createUser(self):
        changed = False
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

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
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

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

    def createGroup(self):
        changed = False
        failed, masters, msg = map(check_new(self).get, ('failed', 'orchestrators', 'msg'))

        cmd = [
            cbcli, 'user-manage',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--set-group',
            '--group-name=' + self.rbac_group_name,
        ]
        if self.rbac_group_roles != "":
            cmd.extend(['--roles=' + ','.join(self.rbac_group_roles)])

        if self.rbac_group_ldap_ref != "":
            cmd.extend(['--ldap-ref', self.rbac_group_ldap_ref])

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
        else:
            failed = True

        msg = msg + stderr

        return dict(failed=failed, changed=changed, msg=msg)

    def deleteGroup(self):
        changed = False
        failed, masters, msg = map(check_new(self).get, ('failed', 'orchestrators', 'msg'))

        cmd = [
            cbcli, 'user-manage',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--delete-group',
            '--group-name=' + self.rbac_group_name
        ]
        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
            msg = msg + " Group has been removed."
        else:
            failed = True
            msg = msg + stderr

        return dict(failed=failed, changed=changed, msg=msg)

### Check functions --> ###
    def check_ldap(self):
        # Not possible to verify if LDAP is enabled -- we just always return changed=True
        if self.ldap_enabled:
            changed = True
            failed = False
            msg = "LDAP will be enabled no matter what. "
        return dict(failed=failed, changed=changed, msg=msg)

    def check_group(self):
        changed = False
        failed = False
        msg = "Everything is configured as requeted"

        all_users = get_users(self)

        # Verify creation
        if self.state == "present":
            if self.rbac_group_name != "":
                # No groups exist, a group should be created
                if all_users['groups'] == []:
                    changed = True
                    msg = " A new group will be created "
                else:
                    new_grp = True
                    for group in all_users['groups']:
                        # Groups exist, verify their names. If match, check the ldap ref and mapping if defined
                        if group['name'] == self.rbac_group_name:
                            new_grp = False
                            if self.rbac_group_ldap_ref != group['ldap_group_ref']:
                                changed = True
                                msg = msg + " LDAP mapping will be changed"
                            if sorted(self.rbac_group_roles) != sorted(group['roles']):
                                changed = True
                                msg = msg + " RBAC group roles will be changed"
                    # Group doesn't exist, has to be created
                    changed = True
                    msg = " A new group will be created"

        # Validate removal
        if self.state == "absent":
            if self.rbac_group_name == "":
                failed = True
                msg = "Please provide a group name to be removed"
            else:
                for group in all_users['groups']:
                    if  group['name'] == self.rbac_group_name:
                        changed = True
                        msg = "A group will be removed"

        return dict(failed=failed, changed=changed, msg=msg)

    def check_user(self):
        # This function is NOT verifying user's password -- because there's no way how to.
        changed = False
        failed = False
        msg = ""


        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        cmd = [
            cbcli, 'user-manage',
            '-c', masters['cluster'],
            '--list',
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
        ]
        rc, stdout, stderr = self.module.run_command(cmd)

        if rc != 0:
            failed = True
        elif self.state == "present":
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
        elif self.state == "absent":
            for item in json.loads(stdout):
                if item['id'] == self.rbac_user_name:
                    msg = msg + "User will be removed. "
                    changed = True
                else:
                    msg = msg + "User not found anyway"

        return dict(failed=failed, changed=changed, msg=msg)




### <-- Check functions ###

    def execute(self):
        if self.ldap_enabled:
            failed,changed,msg = map(self.enable_ldap().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=changed,msg=msg)

        if self.state == "absent":
            if self.rbac_user_name != "":
                failed,changed,msg = map(self.check_user().get, ('failed','changed','msg'))
                if not failed and changed:
                    failed,changed,msg = map(self.deleteUser().get, ('failed','changed','msg'))
            if self.rbac_group_name != "":
                failed,changed,msg = map(self.check_group().get, ('failed','changed','msg'))
                if not failed and changed:
                    failed,changed,msg = map(self.deleteGroup().get, ('failed','changed','msg'))

            return dict(failed=failed,changed=changed,msg=msg)

        # Because there is no way how to verify user's password, let's say it's always runs and always "changed".
        if self.state == "present":
            if self.rbac_user_name != "":
                failed,changed,msg = map(self.createUser().get, ('failed','changed','msg'))
            if self.rbac_group_name != "":
                failed,changed,msg = map(self.check_group().get, ('failed','changed','msg'))
                if changed and not failed:
                    failed,changed,msg = map(self.createGroup().get, ('failed','changed','msg'))

            return dict(failed=failed,changed=changed,msg=msg)


def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        # RBAC config
        ldap_enabled=dict(required=False, default=False, type="bool"),
        ldap_hosts=dict(required=False),
        ldap_port=dict(required=False),
        ldap_encryption=dict(required=False, default="none", choices=["tls", "startTLS", "none"]),
        ldap_user_dn_template=dict(required=False),
        ldap_cacert_path=dict(required=False),
        ldap_bind_dn=dict(required=False),
        ldap_bind_password=dict(required=False),
        rbac_group_name=dict(required=False, default=""),
        rbac_group_roles=dict(required=False, default=[], type="list"),
        rbac_group_ldap_ref=dict(required=False, default=""),
        state=dict(required=False, default="present", choices=["present", "absent"]),
        user_type=dict(required=False, default="local", choices=["local", "external"]),
        rbac_user_name=dict(required=False, default=""),
        rbac_user_password=dict(required=False),
        rbac_roles=dict(required=False, default=[], type="list")
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

    if module.check_mode:
        if module.params['ldap_enabled'] == True:
            result = Couchbase(module).check_ldap()
            module.exit_json(**result)
        if module.params['state'] == "present" or module.params['state'] == "absent":
            result = Couchbase(module).check_user()
            module.exit_json(**result)

    result = Couchbase(module).execute()

    module.exit_json(**result)

if __name__ == '__main__':
        main()
