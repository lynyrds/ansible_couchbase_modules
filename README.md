# Ansible modules for Couchbase

## couchbase_cluster

* Init a Couchbase cluster
* Join nodes to a Couchbase cluster
* Rebalance a Couchbase cluster
 
### Prerequisites
* Ansible > 2.2
* python requests installed
* Couchbase cluster binaries installed

### Installing
Place these modules in some folder present in the `ANSIBLE_LIBRARY` path variable, or alongside playbook under `./library`

### Notes
* The list of all nodes is needed to reliably detect the cluster's orchestrator.
* Tasks to init and rebalance should be set to run once (`run_once: True`)
* Check mode is supported
* Rebalance won't be issued if a bucket is found. Use `force: True` to rebalance anyway.
* Tested on RHEL6 with Ansible 2.2.1 and Couchbase Enterprise 5.0 April build

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

  - name: "Join nodes"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
    join: True

  - name: "Rebalance"
    couchbase_cluster:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
    rebalance: True
```
