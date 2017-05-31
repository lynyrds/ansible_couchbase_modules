# Ansible modules for Couchbase

## couchbase_cluster

* Init a Couchbase cluster
* Join nodes to a Couchbase cluster
* Create a Couchbase or Ephemeral bucket
* Rebalance a Couchbase cluster
* Enable LDAP authentication
* Create RBAC user
* Delete RBAC user
 
### Prerequisites
* Ansible >= 2.3
* python requests installed
* Couchbase cluster binaries installed

### Installing
Place these modules in some folder present in the `ANSIBLE_LIBRARY` path variable, or alongside playbook under `./library`

### Notes
* The list of all nodes is needed to reliably detect the cluster's orchestrator.
* Tasks to init, rebalance and bucket create should be set to run once (`run_once: True`)
* Check mode is supported, but not for enabling LDAP as there is no way to verify if it is enabled or not
* RBAC user create is checked for everything but password. That means, create_user: True is going to be executed every time.
* For more details on RBAC please refer to the official Couchbase documentation:
  https://developer.couchbase.com/documentation/server/5.0/security/security-authorization.html
* Rebalance won't be issued if a bucket is found. Use `force: True` to rebalance anyway.
* For more details on LDAP/PAM authentication please refer to the official Couchbase documentation: 
  https://developer.couchbase.com/documentation/server/5.0/security/security-authentication.html
* 
* Tested on RHEL6 with Ansible 2.3 and Couchbase Enterprise 5.0 beta build

### Example playbook

```yaml
---
- hosts: all
  tasks:
  - name: "Init cluster"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
      init: True
      cluster_mem: 1024
    run_once: True
    no_log: True

  - name: "Join nodes"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
      join: True
    no_log: True

  - name: "Rebalance"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
      rebalance: True
    run_once: True
    no_log: True

  - name: "Enable LDAP"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
      ldap_enabled: True
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
```
