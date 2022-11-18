#!/usr/bin/python2

# Change log:
# 2018-07-12: Initial commit
# 2018-07-31: Support moving server(s) from any to any group
# 2018-08-02: Add node's health check
# 2020-09-30: Add 6.5 support: CB version check, user and group list
# 2022-01-22: Dropped support for all versions below 6.6, now looking for the orchestrator using the official REST API
#             https://docs.couchbase.com/server/current/rest-api/rest-identify-orchestrator.html
# 2022-11-18: Fixed orchestrator detection
#
# Copyright: (c) 2018, Michael Hirschberg <lynyrd@gmail.com>
# 
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# couchbase_common is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# couchbase_common is distributed in the hope that it will be useful,
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

# This file is hosting common functions for all the couchbase modules


from time import sleep
import socket
import requests
import json
import os

cbcli = "/opt/couchbase/bin/couchbase-cli"
my_fqdn = socket.getfqdn()
my_name = socket.gethostname()
default = "127.0.0.1"
all_cl_membership = ["active", "inactiveFailed", "inactiveAdded"]
all_node_status = ["healthy", "warmup", "unhealthy"]
tls_min_version = "tlsv1.2"
disabled_users = ['@ns_server/local', '@cbq-engine/local', '@projector/local', '@goxdcr/local', '@index/local']

def check_new(cluster):
    # Check if it's a new cluster / node
    # Expects a full list of cluster nodes
    # Returns :
    # - failed = True | False
    # - cluster orchestrator
    # - local node's orchestrator
    # - a message
    # Fails :
    # If all nodes don't have an orchestrator
    all_orchestrators = []
    orchestra = []
    orchestrators = {}
    msg = ""
    failed = False
    port = str(cluster.admin_port)
    my_orch = ""

    def get_master(my_node):
        url = "http://" + my_node + ":" + port + "/pools/default/terseClusterInfo"
        orch = ""
        try:
            tmp_orch = requests.get(url, auth=(cluster.cb_admin,cluster.admin_password))
            if tmp_orch.status_code == 200:
                orch = tmp_orch.json()['orchestrator']
            else:
                orch = default
        except:
            orch = "failed"
        return orch

    # Build a list of all orchestrators
    for node in cluster.nodes:
        my_orch = get_master(node)
        if my_orch != "failed":
            all_orchestrators.append(my_orch)
        else:
            failed = True

    # Get cluster orchestrator
    orchestra = list(set(all_orchestrators))
    if len(orchestra) == 1 and default == orchestra[0]:
        orchestrators['cluster'] = default
    else:
        for orchestrant in orchestra:
            if orchestrant != default:
                orchestrators['cluster'] = orchestrant[5:]
                
    # Now, let's get a local one
    my_orch = get_master(default)
    orchestrators['local'] = my_orch
    if my_orch != "failed":
        if default in my_orch or my_name in my_orch:
            orchestrators['local'] = default
        else:
            orchestrators['local'] = orchestrators['cluster']
    else:
        failed = True

    if failed:
        msg = "Not all nodes are running couchbase-server!"

    return dict(failed=failed, orchestrators=orchestrators, msg=msg)

def get_my_group(cluster):
    # This function assumes the cluster is already configured

    # Get all groups/servers information first
    port = str(cluster.admin_port)
    my_groups = {}
    my_group = ""
    me = my_fqdn + ":" + port
    url = "http://" + default + ":" + port + "/pools/default/serverGroups"
    data = json.loads(requests.get(url,auth=(cluster.cb_admin,cluster.admin_password)).text)

    for item in data['groups']:
        group = item['name']
        my_groups[group] = []
        for node in item['nodes']:
            if "hostname" in node:
                my_groups[group].append(node['hostname'])

    # Now, find the group we're in
    for group,nodes in my_groups.items():
        if me in nodes:
            my_group = group

    return my_group

def move_node(cluster):
    port = str(cluster.admin_port)
    group_in = get_my_group(cluster)
    group_to = cluster.group
    rc = 0
    stdout = "Already in the right group"
    stderr = ""

    if group_in != group_to:
        # First, create the group your server is in
        # We don't really care if the group exists or not, we just run the cmd
        cmd = [
            cbcli, 'group-manage',
            '--group-name=' + group_to,
            '--create',
            '--cluster=localhost',
            '--username=' + cluster.cb_admin, '--password=' + cluster.admin_password
        ]
        rc, stdout, stderr = cluster.module.run_command(cmd)

        # Second, move the server to the right group
        cmd = [
            cbcli, 'group-manage',
            '--move-servers', my_fqdn,
            '--from-group=' + group_in,
            '--to-group=' + group_to,
            '--cluster=localhost',
            '--username=' + cluster.cb_admin,
            '--password=' + cluster.admin_password
        ]

        rc, stdout, stderr = cluster.module.run_command(cmd)

    return dict(rc=rc, stdout=stdout, stderr=stderr)

def get_health(cluster):
    # Return a dictionary, each node's available actions (canJoin, canReJoin, canFailOver, canRemove, canEdit)
    # And some other things like "balanced" and "services"

    # Get all groups/servers information first
    port = str(cluster.admin_port)
    all_health = {}
    me = my_fqdn + ":" + port
    url = "http://" + default + ":" + port + "/pools/nodes"
    health = json.loads(requests.get(url,auth=(cluster.cb_admin,cluster.admin_password),timeout=5).text)

    my_report = {
        'canJoin': False,
        'canReJoin': False,
        'canFailOver': False,
        'canRemove': False,
        'canEdit': False,
        'services': []
    }

    my_health = {}

    try:
        for node in health['nodes']:
            if node['hostname'] == me:
                my_health = {
                    "membership": node['clusterMembership'],
                    "status": node['status'],
                    "services": node['services'],
                    "version": node['version'].split("-")[0]
                }
        my_report['services'] = my_health['services']
        my_report['version'] = my_health['version']
        if my_health['membership'] == "active" and my_health['status'] == "healthy":
            my_report['canEdit'] = True
            my_report['canFailOver'] = True
            my_report['canRemove'] = True
        if my_health['membership'] == "inactiveAdded" and my_health['status'] == "healthy":
            my_report['canFailOver'] = True
            my_report['canRemove'] = True
        if my_health['membership'] == "active" and my_health['status'] == "unhealthy":
            my_report['canFailOver'] = True
        if my_health['membership'] == "inactiveFailed" and my_health['status'] == "healthy":
            my_report['canReJoin'] = True

    except:
        if health == "unknown pool":
            my_report['canJoin'] = True

    return my_report

def get_users(cluster):
    # Return a dictionary of all registered local and extrernal users and groups. Supported only for CB > 6.5.x
    all_users = {
        "local": [],
        "external": [],
        "groups": []
    }

    port = str(cluster.admin_port)

    url = "http://" + default + ":" + port + "/settings/rbac/users"
    users = json.loads(requests.get(url,auth=(cluster.cb_admin,cluster.admin_password),timeout=5).text)

    url = "http://" + default + ":" + port + "/settings/rbac/groups"
    grps = json.loads(requests.get(url,auth=(cluster.cb_admin,cluster.admin_password),timeout=5).text)

    if users != []:
        for user in users:
            my_user = {}
            my_roles = []

            my_user['name'] = user['id']
            for role in user['roles']:
                my_roles.append(role['role'])
            my_user['roles'] = my_roles
            my_user['external_groups'] = user['external_groups']
            my_user['groups'] = user['groups']

            all_users[user['domain']].append(my_user)


    if grps != []:
        for grp in grps:
            my_grp = {}
            my_roles = []

            my_grp['name'] = grp['id']
            my_grp['ldap_group_ref'] = grp['ldap_group_ref']
            for role in grp['roles']:
                my_roles.append(role['role'])
            my_grp['roles'] = my_roles

            all_users['groups'].append(my_grp)

    return all_users
