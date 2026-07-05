@serial
@cradle_nodeport
Feature: NodePort and hostPort — services on the node's own IP
  A pod behind a service is reachable at the node's uplink IP on a chosen
  port. The node IP is a local address, but l4_nat's SERVICES lookup runs
  before the local-punt, so `<nodeIP>:<port>` DNATs to a backend and the
  reverse-SNAT returns the reply from `<nodeIP>:<port>`. hostPort is driven
  by the real cradle-cni via the CNI portMappings capability; NodePort is
  the same node-IP frontend (programmed here over gRPC, as cradle-k8s does
  from a NodePort Service). Kernel forwarding on the node is off. Design:
  docs/design/kube-proxy-dualstack.md (K3).

  Topology:
  ```
   ext(203.0.113.9) ── n0 [node: cradle, uplink 203.0.113.1] crdl* ── pod1(10.244.0.2:8080)
                        hostPort 30080→8080 (cradle-cni), NodePort 31000→8080 (gRPC)
  ```

  Scenario: Reach a pod via hostPort and via a node-IP NodePort frontend
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "ext"
    And I create namespace "pod1"
    And I connect namespace "node" interface "n0" to namespace "ext" interface "eth0"
    And I add address "203.0.113.1/24" to interface "n0" in namespace "node"
    And I add address "203.0.113.9/24" to interface "eth0" in namespace "ext"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni-hostport.json" expecting "10.244.0.2"
    And I serve HTTP "hi" in namespace "pod1" bound to "10.244.0.2"
    # hostPort 30080 → pod:8080, programmed by cradle-cni from portMappings.
    Then HTTP GET "http://203.0.113.1:30080/" from namespace "ext" should contain "hi"
    And the cradle stat "l4_dnat" in namespace "node" via gRPC as "ctl" should be nonzero
    When I apply cradle config "nodeport-svc.json" to namespace "node" via gRPC as "ctl"
    # NodePort 31000 → pod:8080, a node-IP frontend (as cradle-k8s programs).
    Then HTTP GET "http://203.0.113.1:31000/" from namespace "ext" should contain "hi"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "pod1"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "ext"
    And I delete namespace "node"
    Then the test environment should be clean
