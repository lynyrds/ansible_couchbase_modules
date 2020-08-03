# Ansible modules for Couchbase

## couchbase_cluster

* Init a Couchbase cluster
* Edit Couchbase cluster settings (cluster name, memory sizing, db compaction, tombstone, failover settings)

## couchbase_node
* Join nodes to a Couchbase cluster
* Move nodes between groups

## couchbase_bucket
* Create a Couchbase or Ephemeral bucket
* Change bucket settings

## couchbase_rbac
* Create RBAC user
* Delete RBAC user

## couchbase_security
* Enable LDAP authentication
* Manage audit
* Restrict TLS to 1.2
* Disable GUI over http

### Prerequisites
* Ansible >= 2.4
* python requests installed
* Couchbase cluster binaries installed, tested on 6.x. Not verified on 6.5.x !

### Installing
Place these modules in some folder present in the `ANSIBLE_LIBRARY` path variable, or alongside playbook under `./library`

### Notes
* The list of all nodes is needed to reliably detect the cluster's orchestrator
* Check mode is not supported for enabling LDAP, setting autofailover and audit, TLS restriction, disable UI over http
* RBAC user create is checked for everything but password. That means, create_user: True is going to be executed every time.
* For more details on RBAC please refer to the official Couchbase documentation:
  https://developer.couchbase.com/documentation/server/5.0/security/security-authorization.html
* For more details on LDAP/PAM authentication please refer to the official Couchbase documentation: 
  https://developer.couchbase.com/documentation/server/5.0/security/security-authentication.html
* For examples please refer to the respective module's documentation

