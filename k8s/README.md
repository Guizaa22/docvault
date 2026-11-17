# Kubernetes (kind + Calico)

Versions used: kind 0.33.0, kubectl v1.37.2, node image kindest/node:v1.37.0, Calico v3.33.0
(`manifests/calico.yaml` from the projectcalico/calico repo at that tag).

The Secret `docvault-secrets` is created by hand from generated values and is never committed.
