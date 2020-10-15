#!/usr/bin/env python

# Change log:
# 2019-07-02: Initial commit
# 2020-09-23: Add support for CB 6.5, add cipher suite setting
# 2020-09-25: Add support for disabled users and audit events
# 2020-09-29: Add support for disabling email notifications and session management
#
# Copyright: (c) 2019, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_security is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_security is distributed in the hope that it will be useful,
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
module: couchbase_security
short_description: Manage Couchbase clusters
description:
    - The M(couchbase_cluster) module can manage different cluster-wide security settings
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
    audit_enabled:
        description:
            - "Enable or disable audit (please use run_once: True in your task!)"
        required: false
    disabled_events:
        description:
            - "Event IDs which should not be audited"
        required: false
    disable_local_users:
        description:
            - "Set to True if local users should not be audited"
        required: false
    audit_log_rotate_interval:
        description:
            - "Audit log rotation interval, in seconds. Default is 86400 (24 hours)"
        required: false
        default: 86400
    audit_log_path:
        description:
            - "Specifies the auditing log path. This should be a path to a folder where the auditing log is kept. The folder must exist on all servers in the cluster."
        required: false
        default: /opt/couchbase/var/lib/couchbase/logs
    restrict_tls:
        description:
            - "Restrict TLS to 1.2  (please use run_once: True in your task!)"
        required: false
    http_ui_enabled:
        description:
            - "Enable or disable the GUI over http (please use run_once: True in your task!)"
        required: false
    enable_notifications:
        description:
            - "Enable or disable update notifications (please use run_once: True in your task!)"
        required: false
    cipher_suites:
        description:
            - "Supported for CB > 6.5.x A comma separated list of ciphers, like TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA"
        required: false
    session_timeout:
        description:
            - "Supported for CB > 6.5.x, a user session timeout in seconds."
        required: false
'''

EXAMPLES = '''
# nodes list is needed to reliably detect the cluster's orchestrator

- name: "Enable audit"
    couchbase_security:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
        audit_enabled: True
    run_once: True
    no_log: True

- name: "Restrict TLS"
    couchbase_security:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
        restrict_tls: True
    run_once: True
    no_log: True

- name: "Disable UI over http"
    couchbase_security:
        cb_admin: Administrator
        admin_password: MySuperSecretPassword
        nodes:
            - node01
            - node02
        http_ui_enabled: False
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
        self.audit_enabled = module.params['audit_enabled']
        self.disable_local_users = module.params['disable_local_users']
        self.disabled_events = module.params['disabled_events']
        self.audit_log_rotate_interval = module.params['audit_log_rotate_interval']
        self.audit_log_path = module.params['audit_log_path']
        self.restrict_tls = module.params['restrict_tls']
        self.http_ui_enabled = module.params['http_ui_enabled']
        self.cipher_suites = module.params['cipher_suites']
        self.session_timeout = module.params['session_timeout']
        self.enable_notifications = module.params['enable_notifications']

    def manage_audit(self):
        changed = False
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))
        enabled_text = "disabled"

        cmd = [
            cbcli, 'setting-audit',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
        ]

        node_state = get_health(self)
        if cb_version_split <= node_state['version']:
            cmd.extend(['--set'])


        if self.audit_enabled:
            cmd.extend(['--audit-enabled=1'])
            cmd.extend([
            '--audit-log-rotate-interval=' + self.audit_log_rotate_interval,
            '--audit-log-path=' + self.audit_log_path,
            ])

            if cb_version_split <= node_state['version']:
                if self.disable_local_users:
                    all_users = get_users(self)
                    for user in all_users['local']:
                        disabled_users.append(user['name']+'/local')
                    my_disabled_users = ','.join(disabled_users)
                    cmd.extend(['--disabled-users=' + my_disabled_users])
                if self.disabled_events != '':
                    cmd.extend(['--disable-events=' + self.disabled_events])
        else:
            cmd.extend(['--audit-enabled=0'])

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
        else:
            failed = True

        msg = msg + stderr

        return dict(failed=failed, changed=changed, msg=msg)

    def manage_tls_cli(self):
        changed = False
        failed = False
        msg = "TLS has been restricted to "
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        cmd = [
            cbcli, 'setting-security',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--set', '--tls-min-version=' + tls_min_version,
        ]

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
            msg = msg + tls_min_version
        else:
            msg = stderr + stdout
            failed = True

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


    def manage_ciphers(self):
        changed = False
        failed = False
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        cmd = [
            cbcli, 'setting-security',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--set', '--cipher-suites=' + self.cipher_suites,
        ]

        rc, stdout, stderr = self.module.run_command(cmd)

        msg = stderr + stdout
        if rc == 0:
            changed = True
        else:
            failed = True

        return dict(failed=failed, changed=changed, msg=msg)

    def manage_session(self):
        changed = False
        failed = False
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        if self.session_timeout != "":
            url = "http://" + default + ":" + self.admin_port + "/settings/security"
            payload = {'uiSessionTimeout': self.session_timeout}
            data = requests.post(url, auth=(self.cb_admin,self.admin_password), data=payload)
            if data.status_code != 200:
                failed = True
            else:
                changed = True
            msg = data.text

        return dict(failed=failed, changed=changed, msg=msg)

    def manage_notifications(self):
        changed = False
        failed = False
        msg = ""
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        if self.enable_notifications == True:
            enable = "1"
        if self.enable_notifications == False:
            enable = "0"

        cmd = [
            cbcli, 'setting-notification',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password
        ]

        node_state = get_health(self)
        if cb_version_split <= node_state['version']:
            cmd.extend(['--enable-notifications=' + enable])
        else:
            cmd.extend(['--enable-notification=' + enable])

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
        else:
            failed = True

        msg = stdout + stderr

        return dict(failed=failed, changed=changed, msg=msg)


    def manage_http_ui_cli(self):
        changed = False
        failed = False
        msg = "UI over http has been "
        disabled = '1'
        disabled_text = "disabled"
        failed,masters,msg = map(check_new(self).get,('failed','orchestrators','msg'))

        if self.http_ui_enabled:
            disabled = '0'
            disabled_text = "enabled"


        cmd = [
            cbcli, 'setting-security',
            '-c', masters['cluster'],
            '--username=' + self.cb_admin, '--password=' + self.admin_password,
            '--set', '--disable-http-ui=' + disabled,
        ]

        rc, stdout, stderr = self.module.run_command(cmd)

        if rc == 0:
            changed = True
            msg = msg + disabled_text
        else:
            msg = stderr + stdout
            failed = True

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

    def execute(self):
        if self.audit_enabled == True or self.audit_enabled == False:
            failed,changed,msg = map(self.manage_audit().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=True,msg=msg)

        if self.enable_notifications == True or self.enable_notifications == False:
            failed,changed,msg = map(self.manage_notifications().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=True,msg=msg)

        if self.restrict_tls == True or self.restrict_tls == False:
            node_state = get_health(self)
            if cb_version_split <= node_state['version']:
                failed,changed,msg = map(self.manage_tls_cli().get, ('failed','changed','msg')) 
            else:
                failed,changed,msg = map(self.manage_tls().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=True,msg=msg)

        if self.http_ui_enabled == True or self.http_ui_enabled == False:
            node_state = get_health(self)
            if cb_version_split <= node_state['version']:
                failed,changed,msg = map(self.manage_http_ui_cli().get, ('failed','changed','msg'))
            else:
                failed,changed,msg = map(self.manage_http_ui().get, ('failed','changed','msg'))
            return dict(failed=failed,changed=True,msg=msg)

        if self.cipher_suites != "":
            node_state = get_health(self)
            if cb_version_split <= node_state['version']:
                failed,changed,msg = map(self.manage_ciphers().get, ('failed','changed','msg'))
            else:
                failed=False
                changed=False
                msg="Not supported on Couchbase <= 6.5"
            return dict(failed=failed,changed=True,msg=msg)

        if self.session_timeout != "":
            node_state = get_health(self)
            if cb_version_split <= node_state['version']:
                failed,changed,msg = map(self.manage_session().get, ('failed','changed','msg'))
            else:
                failed=False
                changed=False
                msg="Not supported on Couchbase <= 6.5"
            return dict(failed=failed,changed=True,msg=msg)

def main():
    fields = dict(
        # Common things
        cb_admin=dict(required=True),
        admin_password=dict(required=True),
        nodes=dict(required=True, type="list"),
        admin_port=dict(default="8091"),
        # Audit config
        audit_enabled=dict(required=False, type='bool'),
        enable_notifications=dict(required=False, type='bool'),
        disable_local_users=dict(required=False, type='bool'),
        disabled_events=dict(required=False),
        audit_log_rotate_interval=dict(required=False, default="86400"),
        audit_log_path=dict(required=False, default="/opt/couchbase/var/lib/couchbase/logs"),
        # Security hardening
        restrict_tls=dict(required=False, type='bool'),
        http_ui_enabled=dict(required=False, type='bool'),
        cipher_suites=dict(required=False, default=""),
        session_timeout=dict(required=False, default="")
    )

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)

    result = Couchbase(module).execute()

    module.exit_json(**result)

if __name__ == '__main__':
        main()
