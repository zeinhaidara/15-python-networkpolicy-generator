import tempfile
import unittest
from pathlib import Path

import yaml

from generator import (
    IntentError,
    build_default_deny,
    build_network_policies,
    load_intent,
    main,
)

SAMPLE_INTENT = """
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
"""


class LoadIntentTests(unittest.TestCase):
    def test_parses_services_and_rules(self):
        services, rules = load_intent(SAMPLE_INTENT)
        self.assertEqual(set(services), {"frontend", "backend"})
        self.assertEqual(
            rules, [{"from": "frontend", "to": "backend", "ports": [{"port": 8080, "protocol": "TCP"}]}]
        )

    def test_rejects_unknown_from_service(self):
        text = """
services:
  - name: backend
    namespace: shop
    selector: {app: backend}
rules:
  - from: ghost
    to: backend
"""
        with self.assertRaises(IntentError):
            load_intent(text)

    def test_rejects_unknown_to_service(self):
        text = """
services:
  - name: frontend
    namespace: shop
    selector: {app: frontend}
rules:
  - from: frontend
    to: ghost
"""
        with self.assertRaises(IntentError):
            load_intent(text)

    def test_rejects_duplicate_service_name(self):
        text = """
services:
  - name: frontend
    namespace: shop
    selector: {app: frontend}
  - name: frontend
    namespace: shop
    selector: {app: frontend}
"""
        with self.assertRaises(IntentError):
            load_intent(text)

    def test_rejects_missing_namespace(self):
        text = """
services:
  - name: frontend
    selector: {app: frontend}
"""
        with self.assertRaises(IntentError):
            load_intent(text)

    def test_rejects_invalid_port(self):
        text = """
services:
  - name: frontend
    namespace: shop
    selector: {app: frontend}
  - name: backend
    namespace: shop
    selector: {app: backend}
rules:
  - from: frontend
    to: backend
    ports:
      - port: 70000
        protocol: TCP
"""
        with self.assertRaises(IntentError):
            load_intent(text)

    def test_rejects_invalid_protocol(self):
        text = """
services:
  - name: frontend
    namespace: shop
    selector: {app: frontend}
  - name: backend
    namespace: shop
    selector: {app: backend}
rules:
  - from: frontend
    to: backend
    ports:
      - port: 80
        protocol: ICMP
"""
        with self.assertRaises(IntentError):
            load_intent(text)


class BuildPolicyTests(unittest.TestCase):
    def test_builds_ingress_and_egress_policies(self):
        services, rules = load_intent(SAMPLE_INTENT)
        policies = build_network_policies(services, rules)
        by_name = {p["metadata"]["name"]: p for p in policies}

        backend_policy = by_name["backend-policy"]
        self.assertEqual(backend_policy["spec"]["policyTypes"], ["Ingress"])
        self.assertEqual(
            backend_policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"],
            {"app": "frontend"},
        )
        self.assertEqual(backend_policy["spec"]["ingress"][0]["ports"], [{"port": 8080, "protocol": "TCP"}])

        frontend_policy = by_name["frontend-policy"]
        self.assertEqual(frontend_policy["spec"]["policyTypes"], ["Egress"])

    def test_service_with_no_rules_denies_all(self):
        text = """
services:
  - name: isolated
    namespace: shop
    selector: {app: isolated}
"""
        services, rules = load_intent(text)
        policies = build_network_policies(services, rules)
        self.assertEqual(policies[0]["spec"]["policyTypes"], ["Ingress", "Egress"])
        self.assertNotIn("ingress", policies[0]["spec"])
        self.assertNotIn("egress", policies[0]["spec"])

    def test_rule_without_ports_allows_all_ports(self):
        text = """
services:
  - name: a
    namespace: ns
    selector: {app: a}
  - name: b
    namespace: ns
    selector: {app: b}
rules:
  - from: a
    to: b
"""
        services, rules = load_intent(text)
        policies = build_network_policies(services, rules)
        by_name = {p["metadata"]["name"]: p for p in policies}
        self.assertNotIn("ports", by_name["b-policy"]["spec"]["ingress"][0])

    def test_cross_namespace_rule_sets_namespace_selector(self):
        text = """
services:
  - name: gateway
    namespace: edge
    selector: {app: gateway}
  - name: billing
    namespace: payments
    selector: {app: billing}
rules:
  - from: gateway
    to: billing
"""
        services, rules = load_intent(text)
        policies = build_network_policies(services, rules)
        by_name = {p["metadata"]["name"]: p for p in policies}
        ns_selector = by_name["billing-policy"]["spec"]["ingress"][0]["from"][0]["namespaceSelector"]
        self.assertEqual(ns_selector["matchLabels"]["kubernetes.io/metadata.name"], "edge")


class DefaultDenyTests(unittest.TestCase):
    def test_one_policy_per_namespace_sorted(self):
        policies = build_default_deny({"shop", "edge"})
        names = [(p["metadata"]["namespace"], p["metadata"]["name"]) for p in policies]
        self.assertEqual(names, [("edge", "default-deny-all"), ("shop", "default-deny-all")])
        self.assertEqual(policies[0]["spec"], {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]})


class MainCliTests(unittest.TestCase):
    def test_main_writes_to_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_path = Path(tmp) / "intent.yaml"
            intent_path.write_text(SAMPLE_INTENT)
            out_dir = Path(tmp) / "out"

            rc = main([str(intent_path), "--output-dir", str(out_dir), "--default-deny"])
            self.assertEqual(rc, 0)

            files = sorted(p.name for p in out_dir.iterdir())
            self.assertIn("shop-default-deny-all.yaml", files)
            self.assertIn("shop-backend-policy.yaml", files)

            doc = yaml.safe_load((out_dir / "shop-backend-policy.yaml").read_text())
            self.assertEqual(doc["kind"], "NetworkPolicy")

    def test_main_returns_nonzero_on_invalid_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_path = Path(tmp) / "intent.yaml"
            intent_path.write_text("services:\n  - name: a\n")
            rc = main([str(intent_path)])
            self.assertEqual(rc, 1)

    def test_main_returns_nonzero_on_missing_file(self):
        rc = main(["/does/not/exist.yaml"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
