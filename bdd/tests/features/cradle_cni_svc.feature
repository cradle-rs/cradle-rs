@serial
@cradle_cni_svc
Feature: ClusterIP-style service on CNI pods via the eBPF L4 load balancer
  The Kubernetes Service model on cradle: pods attached by cradle-cni are
  the backends of a virtual IP that exists only in the eBPF SERVICES map —
  a client pod's connection to the VIP is DNATed to a backend pod (and
  conntracked, replies SNATed back) entirely in the datapath. AddService
  replaces a service's backend set in place; DelService removes it. These
  two RPCs are the reconcile surface the cradle-k8s Service controller
  drives. Kernel forwarding stays off — only eBPF carries the traffic.

  Topology (single node):
  ```
   [node: cradle serve] crdl* ── pod1(b1), pod2(b2) backends :8080; pod3 client
                                  VIP 10.96.0.10:80 (eBPF only — no interface)
  ```

  Scenario: A VIP balances across pod backends, shrinks, and deletes
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I create namespace "pod3"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    And I run CNI ADD for container "pod3" in pod namespace "pod3" on node "node" with config "cni.json" expecting "10.244.0.4"
    And I serve HTTP "b1" in namespace "pod1" bound to "10.244.0.2"
    And I serve HTTP "b2" in namespace "pod2" bound to "10.244.0.3"
    And I apply cradle config "svc.json" to namespace "node" via gRPC as "ctl"
    Then HTTP GET "http://10.96.0.10/" from namespace "pod3" should eventually succeed
    And HTTP GET "http://10.96.0.10/" from namespace "pod3" returns at least 2 distinct responses over 12 requests
    And the cradle stat "l4_dnat" in namespace "node" via gRPC as "ctl" should be nonzero
    When I apply cradle config "svc-one.json" to namespace "node" via gRPC as "ctl"
    Then HTTP GET "http://10.96.0.10/" from namespace "pod3" returns only "b1" over 8 requests
    When I delete cradle service "10.96.0.10" port 80 via gRPC as "ctl" in namespace "node"
    Then HTTP GET "http://10.96.0.10/" from namespace "pod3" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "pod1"
    And I stop HTTP in namespace "pod2"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "pod3"
    And I delete namespace "node"
    Then the test environment should be clean
