# NetworkPolicy generator

A Python CLI that turns a small YAML "intent" file — which services exist and
which ones are allowed to talk to which, on what ports — into Kubernetes
`NetworkPolicy` YAML.

**Scope.** This is a pure text generator: it reads an intent file and writes
YAML, either to stdout or to a directory of files. It never talks to a
cluster, never calls `kubectl apply`, and has no Kubernetes client
dependency. Applying the generated policies and verifying they behave as
expected on a real cluster is on the user.

## Architecture

- `generator.py` — the whole tool.
  - `load_intent` parses the intent YAML into a `services` dict and a list
    of `rules`, validating service names, namespaces, selectors, ports, and
    protocols.
  - `build_network_policies` builds one `NetworkPolicy` per service: rules
    where the service is the `to` become `ingress` entries, rules where it's
    the `from` become `egress` entries. A service named in no rule gets a
    policy with empty `ingress`/`egress` lists, which denies all traffic to
    and from it.
  - `build_default_deny` optionally adds one deny-all policy per namespace,
    meant to be applied alongside the per-service allow policies.
- Output is either one multi-document YAML stream on stdout, or one file per
  policy under `--output-dir`.

## Intent file format

```yaml
services:
  - name: frontend
    namespace: shop
    selector:
      app: frontend
  - name: backend
    namespace: shop
    selector:
      app: backend

rules:
  - from: frontend
    to: backend
    ports:
      - port: 8080
        protocol: TCP
```

- `services[].selector` becomes the `podSelector.matchLabels` for that
  service's policy and for peer entries that reference it.
- `rules[].ports` is optional; omitting it allows all ports/protocols for
  that rule. When present, `protocol` defaults to `TCP` and must be one of
  `TCP`, `UDP`, `SCTP`.
- `from`/`to` in a rule must both be names declared in `services`; `from`
  and `to` services may be in different namespaces (see
  [`examples/cross-namespace-intent.yaml`](examples/cross-namespace-intent.yaml)).

## Prerequisites

- Python 3.12+
- `pip install -r requirements.txt` (just `pyyaml`)

## Usage

```bash
# print generated NetworkPolicy YAML to stdout
python generator.py examples/sample-intent.yaml

# write one file per policy
python generator.py examples/sample-intent.yaml --output-dir policies/

# also emit a default-deny-all policy per namespace referenced
python generator.py examples/sample-intent.yaml --default-deny
```

Running the first command against
[`examples/sample-intent.yaml`](examples/sample-intent.yaml) produces a
`backend-policy` with an ingress rule from `frontend` on port 8080, and a
`frontend-policy` with only an egress rule to `backend` — `frontend` isn't
named as a `to` in any rule, so nothing can reach it.

## Security considerations

- Treat `--default-deny` as the safe default for any namespace adopting
  this: apply the deny-all policy first (or atomically with the allow
  policies), otherwise there's a window where everything is still open.
- The generator only ever widens access based on what's written in the
  intent file — it never infers or guesses a rule. Review the rendered YAML
  before applying it, the same as any other manifest.
- Selectors are label-based, matching Kubernetes' own `NetworkPolicy`
  semantics: a pod without the expected labels is not covered by a policy
  meant for it, which can silently leave it unprotected or unreachable.
- No secrets, credentials, or cluster endpoints are read or required.

## Idempotency

Generation is pure: the same intent file always produces byte-identical
YAML, and running the tool never mutates the intent file or any existing
output directory contents beyond overwriting the policy files it's about to
regenerate.

## Validation

```bash
pip install -r requirements-test.txt
python -m unittest discover -s tests
```

Tests cover valid and invalid intent files (unknown service references,
duplicate names, invalid ports/protocols), cross-namespace rules, the
rule-less "deny all" case, `--default-deny`, and the `--output-dir` CLI path.
No cluster or network access is required.
