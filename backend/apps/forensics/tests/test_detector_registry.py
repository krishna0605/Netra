from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from common.analysis import _behavior_candidates
from common.detection import DETECTOR_REGISTRY, classify_detection, load_rules
from common.readiness import ml_model_status_payload


class DetectorRegistryTests(SimpleTestCase):
    def test_public_rules_are_exactly_the_runtime_registry(self):
        public_ids = {rule["id"] for rule in load_rules()}
        self.assertEqual(public_ids, set(DETECTOR_REGISTRY))
        self.assertTrue(all(rule["productionActive"] for rule in load_rules()))

    def test_runtime_candidates_reference_only_registered_rules(self):
        features = {
            "summary": {
                "maxDestinationFanout": 100,
                "beaconPairs": 2,
                "externalHostCount": 2,
                "dnsQueryCount": 50,
                "longestDnsQuery": 120,
                "icmpLargePacketCount": 4,
                "largestSessionBytes": 6_000_000,
            },
            "hosts": [{"ip": "192.0.2.10", "uniqueDestinations": 100, "uniqueDestinationPorts": 120, "sensitivePortsTouched": [22, 23, 445]}],
            "services": [
                {"port": 21, "service": "FTP", "sessionCount": 25, "packetCount": 50},
                {"port": 23, "service": "TELNET", "sessionCount": 6, "destinationCount": 6, "packetCount": 20},
                {"port": 3632, "service": "DISTCC", "sessionCount": 1, "packetCount": 1},
            ],
        }
        candidates = _behavior_candidates(features, {"summary": {"sshSessions": 21}})
        self.assertTrue(candidates)
        self.assertTrue({row["ruleId"] for row in candidates}.issubset(DETECTOR_REGISTRY))

    def test_keyword_classification_uses_same_registry(self):
        matches = classify_detection({"message": "repeated ssh authentication"})
        self.assertEqual(matches[0]["ruleId"], "rule-bruteforce-ssh-ftp")

    def test_executable_model_is_absent_and_readiness_is_honest(self):
        model_path = Path(settings.BASE_DIR).parent / "ml-services" / "anomaly-engine" / "models" / "anomaly-model.pkl"
        self.assertFalse(model_path.exists())
        status = ml_model_status_payload()
        self.assertEqual(status["status"], "insufficient_training_data")
        self.assertIsNone(status["f1"])
        self.assertFalse(status["productionApproved"])
