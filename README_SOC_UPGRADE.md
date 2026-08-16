# SOC upgrade

Previous implementation is backed up under:

`backup/2026-08-16-pre-tetragon-soc-v2/`

Replaced: `app/models.py`, `app/detector.py`, `app/context.py`, `app/policy.py`,
`app/main.py`, `requirements.txt`, `Dockerfile`.

Added: `app/tetragon.py`, `collector/tetragon_collector.py`,
`k8s/soc-collector.yaml`, `tetragon/network-connect.yaml`.

`app/store.py` remains unchanged because it stores the full Detection JSON.

For `ls -la /tmp`, a normal PROCESS_EXEC should stay LOW. UID 0 adds only a
small contextual score; `ls` is a common read-only utility, so absent additional
signals the risk is capped at 0.10 and action is ALLOW. No network path is shown
unless Tetragon actually emitted network telemetry.

Build and deploy:

    docker build -t your-registry/ai-security-platform:2.0.0 .
    docker push your-registry/ai-security-platform:2.0.0

    kubectl apply -f tetragon/network-connect.yaml
    kubectl apply -f k8s/soc-collector.yaml

Verify Tetragon independently:

    kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon \
      -c export-stdout -f

Keep enforcement simulated or approval-gated until trusted IOC feeds,
workload baselines, incident correlation and a real enforcement adapter are added.
