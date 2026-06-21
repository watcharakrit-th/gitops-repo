#!/usr/bin/env bash
# Harden the running "lab" kind cluster's control-plane:
#   1. API server audit logging
#   2. etcd encryption at rest (Secrets)
#   3. Re-encrypt existing Secrets under the new provider
#
# Idempotent: safe to re-run. Operates on the live `lab-control-plane`
# container via docker exec/cp — kubelet auto-restarts the kube-apiserver
# static pod when its manifest changes (~20-40s).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE="lab-control-plane"
SECRETS_DIR="${SCRIPT_DIR}/../vault/k8s-secrets"
mkdir -p "$SECRETS_DIR"

echo "==> 1. Audit policy"
docker exec "$NODE" mkdir -p /etc/kubernetes/audit /var/log/kubernetes
docker cp "${SCRIPT_DIR}/audit-policy.yaml" "${NODE}:/etc/kubernetes/audit/audit-policy.yaml"
echo "    audit-policy.yaml -> ${NODE}:/etc/kubernetes/audit/audit-policy.yaml"

echo "==> 2. Encryption-at-rest config"
ENC_FILE="${SECRETS_DIR}/encryption-config.yaml"
if [[ -f "$ENC_FILE" ]]; then
  echo "    ${ENC_FILE} already exists — reusing existing key"
else
  KEY=$(head -c 32 /dev/urandom | base64)
  cat > "$ENC_FILE" << EOF
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${KEY}
      - identity: {}
EOF
  chmod 600 "$ENC_FILE"
  echo "    generated new key -> ${ENC_FILE}"
fi
docker exec "$NODE" mkdir -p /etc/kubernetes/enc
docker cp "$ENC_FILE" "${NODE}:/etc/kubernetes/enc/encryption-config.yaml"
docker exec "$NODE" chmod 600 /etc/kubernetes/enc/encryption-config.yaml
echo "    encryption-config.yaml -> ${NODE}:/etc/kubernetes/enc/encryption-config.yaml"

echo "==> 3. Patch kube-apiserver static pod manifest"
MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
TMP_IN=$(mktemp)
TMP_OUT=$(mktemp)
docker exec "$NODE" cat "$MANIFEST" > "$TMP_IN"

python3 - "$TMP_IN" "$TMP_OUT" << 'PYEOF'
import sys, yaml

src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    doc = yaml.safe_load(f)

container = doc["spec"]["containers"][0]
cmd = container["command"]

new_flags = [
    "--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml",
    "--audit-log-path=/var/log/kubernetes/audit.log",
    "--audit-log-maxage=7",
    "--audit-log-maxbackup=3",
    "--audit-log-maxsize=100",
    "--encryption-provider-config=/etc/kubernetes/enc/encryption-config.yaml",
]
existing_flags = {f.split("=")[0] for f in cmd if f.startswith("--")}
changed = False
for flag in new_flags:
    name = flag.split("=")[0]
    if name not in existing_flags:
        cmd.append(flag)
        changed = True

mounts = container.setdefault("volumeMounts", [])
volumes = doc["spec"].setdefault("volumes", [])
existing_mounts = {m["name"] for m in mounts}
existing_vols = {v["name"] for v in volumes}

extra = [
    ("audit-policy", "/etc/kubernetes/audit", True),
    ("audit-log",    "/var/log/kubernetes", False),
    ("encryption-config", "/etc/kubernetes/enc", True),
]
for name, path, readonly in extra:
    if name not in existing_mounts:
        m = {"mountPath": path, "name": name}
        if readonly:
            m["readOnly"] = True
        mounts.append(m)
        changed = True
    if name not in existing_vols:
        volumes.append({
            "name": name,
            "hostPath": {"path": path, "type": "DirectoryOrCreate"},
        })
        changed = True

with open(dst, "w") as f:
    yaml.safe_dump(doc, f, default_flow_style=False, sort_keys=False)

print("CHANGED" if changed else "UNCHANGED")
PYEOF

RESULT=$(python3 - "$TMP_IN" "$TMP_OUT" << 'PYEOF'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    a = yaml.safe_load(f)
with open(dst) as f:
    b = yaml.safe_load(f)
print("CHANGED" if a != b else "UNCHANGED")
PYEOF
)

if [[ "$RESULT" == "UNCHANGED" ]]; then
  echo "    manifest already hardened — no changes needed"
else
  # IMPORTANT: kubelet's static-pod source scans every file in
  # /etc/kubernetes/manifests/ and treats each as a pod manifest. Backups
  # must NOT live in that directory (an old + new manifest both defining
  # "kube-apiserver" makes kubelet flip-flop between the two specs).
  docker exec "$NODE" mkdir -p /etc/kubernetes/manifests-backup
  BACKUP="/etc/kubernetes/manifests-backup/kube-apiserver.yaml.bak-$(date +%Y%m%d-%H%M%S)"
  docker exec "$NODE" cp "$MANIFEST" "$BACKUP"
  echo "    backed up current manifest to ${NODE}:${BACKUP}"

  # docker cp into a live bind-mounted file isn't atomic and can race with
  # kubelet's fsnotify watcher (it may read a partially-written file). Copy
  # to a temp path in the same directory, then atomically rename into place.
  docker cp "$TMP_OUT" "${NODE}:${MANIFEST}.new"
  docker exec "$NODE" mv "${MANIFEST}.new" "$MANIFEST"
  echo "    patched manifest written — kubelet will restart kube-apiserver"

  echo "==> Waiting for kube-apiserver to come back up..."
  for i in $(seq 1 30); do
    sleep 2
    if kubectl get --raw='/readyz' &>/dev/null; then
      echo "    apiserver ready after ${i}*2s"
      break
    fi
  done
fi
rm -f "$TMP_IN" "$TMP_OUT"

echo "==> 4. Re-encrypting existing Secrets under the new provider"
kubectl get secrets --all-namespaces -o json | kubectl replace -f - >/dev/null
echo "    done"

echo
echo "Verify:"
echo "  docker exec ${NODE} tail -5 /var/log/kubernetes/audit.log"
echo "  docker exec ${NODE} sh -c 'ETCDCTL_API=3 etcdctl --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key get /registry/secrets/default/<name> | strings | grep k8s:enc'"
