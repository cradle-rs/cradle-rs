@serial
@cradle_affinity
Feature: Session affinity (sessionAffinity: ClientIP)
  A service with ClientIP affinity pins each client to one backend: the
  datapath records the chosen backend slot per (service, client IP) and
  reuses it for the client's later flows, instead of picking randomly. The
  same two backends without affinity spread the requests. Kernel forwarding
  is off. Design: docs/design/kube-proxy-dualstack.md (K5).

  Topology (single node, two CNI pod backends + a client pod):
  ```
   pod-cli(10.244.0.4) ─ crdl* [node: cradle serve] ── pod-b1(a), pod-b2(b) :8080
                          VIP 10.96.0.50:80 → {b1, b2}, sessionAffinity ClientIP
  ```

  Scenario: A client sticks to one backend with ClientIP affinity
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "b1"
    And I create namespace "b2"
    And I create namespace "cli"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "b1" in pod namespace "b1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "b2" in pod namespace "b2" on node "node" with config "cni.json" expecting "10.244.0.3"
    And I run CNI ADD for container "cli" in pod namespace "cli" on node "node" with config "cni.json" expecting "10.244.0.4"
    And I serve HTTP "backend-a" in namespace "b1" bound to "10.244.0.2"
    And I serve HTTP "backend-b" in namespace "b2" bound to "10.244.0.3"
    And I apply cradle config "svc.json" to namespace "node" via gRPC as "ctl"
    Then HTTP GET "http://10.96.0.50/" from namespace "cli" should eventually succeed
    And HTTP GET "http://10.96.0.50/" from namespace "cli" returns a single backend over 12 requests

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "b1"
    And I stop HTTP in namespace "b2"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "b1"
    And I delete namespace "b2"
    And I delete namespace "cli"
    And I delete namespace "node"
    Then the test environment should be clean
