#!/usr/bin/env python

# Change log:
# 2019-07-02: Initial commit
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

class Couchbase(object):
    def __init__(self, module):
        self.module = module
        self.cb_admin = module.params['cb_admin']
        self.admin_password = module.params['admin_password']
        self.admin_port = module.params['admin_port']
        self.nodes = module.params['nodes']
        self.ldap_enabled = module.params['ldap_enabled']
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

### Check functions --> ###
    def check_ldap(self):
        # Not possible to verify if LDAP is enabled -- we just always return changed=True
        if self.ldap_enabled:
            changed = True
            failed = False
            msg = "LDAP will be enabled no matter what. "
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
            failed,changed,msg = map(self.check_user().get, ('failed','changed','msg'))
            if not failed and changed:
                failed,changed,msg = map(self.deleteUser().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=changed,msg=msg)

        # Because there is no way how to verify user's password, let's say it's always runs and always "changed".
        if self.state == "present":
            failed,changed,msg = map(self.createUser().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=True,msg=msg)

def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        # RBAC config
        ldap_enabled=dict(required=False, default=False, type="bool"),
        state=dict(required=False, default="present", choices=["present", "absent"]),
        user_type=dict(required=False, default="local", choices=["local", "external"]),
        rbac_user_name=dict(required=False),
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
