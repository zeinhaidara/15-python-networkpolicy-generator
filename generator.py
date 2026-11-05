"""Generate Kubernetes NetworkPolicy YAML from a small intent file."""

import argparse
import sys
from pathlib import Path

import yaml

VALID_PROTOCOLS = {"TCP", "UDP", "SCTP"}


class IntentError(ValueError):
    """Raised when the intent file is missing fields or references unknown services."""


def load_intent(text):
    data = yaml.safe_load(text) or {}

    services = {}
    for svc in data.get("services", []):
        name = svc.get("name")
        if not name:
            raise IntentError("service entry missing 'name'")
        if name in services:
            raise IntentError(f"duplicate service name: {name}")
        namespace = svc.get("namespace")
        if not namespace:
            raise IntentError(f"service '{name}' missing 'namespace'")
        selector = svc.get("selector")
        if not selector:
            raise IntentError(f"service '{name}' missing 'selector'")
        services[name] = {"namespace": namespace, "selector": selector}

    rules = []
    for i, rule in enumerate(data.get("rules", [])):
        src = rule.get("from")
        dst = rule.get("to")
        if src not in services:
            raise IntentError(f"rule {i}: unknown 'from' service {src!r}")
        if dst not in services:
            raise IntentError(f"rule {i}: unknown 'to' service {dst!r}")

        ports = []
        for p in rule.get("ports", []):
            port = p.get("port")
            protocol = p.get("protocol", "TCP")
            if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
                raise IntentError(f"rule {i}: invalid port {port!r}")
            if protocol not in VALID_PROTOCOLS:
                raise IntentError(f"rule {i}: invalid protocol {protocol!r}")
            ports.append({"port": port, "protocol": protocol})

        rules.append({"from": src, "to": dst, "ports": ports})

    return services, rules


def _peer_entry(peer):
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": peer["namespace"]}},
        "podSelector": {"matchLabels": peer["selector"]},
    }


def build_network_policies(services, rules):
    """Build one NetworkPolicy per service, derived from the rules that name it."""
    policies = []
    for name, svc in services.items():
        ingress_rules = []
        for rule in rules:
            if rule["to"] != name:
                continue
            entry = {"from": [_peer_entry(services[rule["from"]])]}
            if rule["ports"]:
                entry["ports"] = rule["ports"]
            ingress_rules.append(entry)

        egress_rules = []
        for rule in rules:
            if rule["from"] != name:
                continue
            entry = {"to": [_peer_entry(services[rule["to"]])]}
            if rule["ports"]:
                entry["ports"] = rule["ports"]
            egress_rules.append(entry)

        spec = {"podSelector": {"matchLabels": svc["selector"]}}
        policy_types = []
        if ingress_rules:
            policy_types.append("Ingress")
            spec["ingress"] = ingress_rules
        if egress_rules:
            policy_types.append("Egress")
            spec["egress"] = egress_rules
        if not policy_types:
            # no rule names this service in either direction: deny all traffic
            policy_types = ["Ingress", "Egress"]
        spec["policyTypes"] = policy_types

        policies.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": f"{name}-policy", "namespace": svc["namespace"]},
                "spec": spec,
            }
        )
    return policies


def build_default_deny(namespaces):
    """One default-deny-all policy per namespace, meant to be applied before the allow policies."""
    return [
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all", "namespace": ns},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        }
        for ns in sorted(namespaces)
    ]


def render(policies):
    return yaml.dump_all(policies, sort_keys=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate NetworkPolicy YAML from an intent file")
    parser.add_argument("intent_file", type=Path)
    parser.add_argument("--output-dir", type=Path, default=None, help="write one file per policy here")
    parser.add_argument(
        "--default-deny", action="store_true", help="also emit a default-deny-all per namespace"
    )
    args = parser.parse_args(argv)

    try:
        text = args.intent_file.read_text()
        services, rules = load_intent(text)
    except (OSError, IntentError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    policies = build_network_policies(services, rules)
    if args.default_deny:
        namespaces = {svc["namespace"] for svc in services.values()}
        policies = build_default_deny(namespaces) + policies

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for policy in policies:
            namespace = policy["metadata"]["namespace"]
            name = policy["metadata"]["name"]
            path = args.output_dir / f"{namespace}-{name}.yaml"
            path.write_text(render([policy]))
    else:
        sys.stdout.write(render(policies))

    return 0


if __name__ == "__main__":
    sys.exit(main())
