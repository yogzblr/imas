change: Owner decision: horizontal scale is validated on Azure with 3 k0s controller/worker nodes for core and 3 for the DMZ, by killing pods and nodes and checking that other pods serve requests (P23, new P24). The rig is for developing the tests.
---
item: P23
action: update
next-append: **Where it is validated (owner, 2026-10-11): on Azure, on 3 k0s nodes for core and 3 for the DMZ (P24), by killing a pod and then a node and checking that the other pods keep serving; the rig is for developing the tests, not the proof.**
---
item: P24
action: add
section: S1
sub: S1c
title: **UAT high-availability topology: 3 k0s nodes for core and 3 for the DMZ** (proposal; owner to confirm the details)
rag: Red
next: Today each hub is one single-node k0s on one VM (`uat/k0s`, kine on SQLite, core on a D8s_v5, DMZ on a D2s_v5, hostPorts on that node). Needed: (1) tofu: three VMs per hub, spread over zones where the region has them, a stable address for each hub's API (Azure load balancer) and for the DMZ's public ports (a Standard load balancer replaces one VM's public IP), NSG and Private DNS updates; (2) `uat/k0s`: three controller+worker nodes with etcd (kine on SQLite does not work with several controllers), a k0sctl config with an external API address, and `bootstrap.sh`/`check.sh` updated for the single-node assumptions (NodePort and hostPort handling); (3) hub values: at least 2 to 3 replicas of farmer, saasapi, Envoy and the bus with topology spread across the nodes (the charts already ship PodDisruptionBudgets); (4) the external services deployed highly available so the node-kill test means something (PXC 3 nodes without `unsafeFlags`, OpenBao 3-node Raft, replicated Valkey, an HA object store, the bus on 3 nodes with an ephemeral `emptyDir` resolver directory and no PVC). Their own HA is taken from their documentation (design D7); (5) a storage decision: local volumes stay on the node that died, so choose replicated storage or accept that stateful pods return only when their node does while the others serve; (6) a new test tier `ha` in `uat/tests`: kill a pod, then stop a node VM, and during it run an API call, a new enrolment and a `cmd.run`; sprouts stay connected or reconnect; define the allowed error window; (7) quota: 3 core nodes of D8s_v5 and 3 DMZ nodes of D2s_v5 are 30 Dsv5 vCPU plus 12 B2ls_v2, against 10 plus 12 today; smaller core nodes (for example D4s_v5) would cut it. Keep the existing single-node run as the plumbing pass; run the HA topology as a separate step after P21 and P23's code are built.
