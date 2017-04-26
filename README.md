# Ansible modules for Couchbase

## cb_find_orchestrator

Reliably detect the orchestrator node for a Couchbase cluster
```
The cluster manager supervises server configuration and interaction between servers within a Couchbase cluster. 
It is a critical component that manages replication and rebalancing operations in Couchbase. 
Although the cluster manager executes locally on each cluster node, it elects a clusterwide orchestrator node  to oversee cluster conditions and carry out appropriate cluster management functions.
```
 
### Prerequisites
* Ansible > 2.1
* python requests installed on the Ansible control machine
* Couchbase cluster

### Installing
Place these modules in some folder present in the `ANSIBLE_LIBRARY` path variable, or alongside playbook under `./library`

### Example playbook

```yaml
---
- hosts: all
  tasks:
  - name: "Get orchestrator"
    cb_find_orchestrator:
      user: Administrator
      password: SuperSecretPassword
      nodes:
        - cb_node01
        - cb_node02
        - cb_node03
    delegate_to: localhost
    register: cmd
    run_once: True

  - name: "Print orchestrator's name"
    debug: msg={{ cmd.orchestrator }}
```

### Possible results
1. A completely new cluster, not initialized:
```
ok: [localhost] => {
    "msg": "127.0.0.1"
}
```
2. At least one node has been initialized (this is probably the node you'll be delegating all Couchbase related tasks to):
```
ok: [localhost] => {
    "msg": "cb_node03"
}
```
3. Couchbase REST API not available (Firewall? No binaries installed? couchbase-server service not started?):
```
fatal: [localhost -> localhost]: FAILED! => {"changed": false, "failed": true, "msg": "Couchbase REST API is not accessible!"}
```
