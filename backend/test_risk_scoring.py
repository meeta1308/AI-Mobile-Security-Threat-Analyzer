import unittest

from app import calculate_advanced_risk, classify_risk_level


class RiskScoringTests(unittest.TestCase):

    def make_app_data(self, requested=None, granted=None, purpose="", category=""):
        return {
            "requested_permissions": requested or [],
            "granted_permissions": granted or [],
            "not_granted_permissions": [],
            "app_purpose": purpose,
            "app_category": category,
        }

    def test_empty_permissions(self):
        data = self.make_app_data()

        result = calculate_advanced_risk(data)

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertTrue(result["limitations"])

    def test_same_input_same_score(self):
        data = self.make_app_data(
            requested=["CAMERA", "RECORD_AUDIO"],
            granted=["CAMERA"],
            purpose="Video recording",
            category="Photography",
        )

        first = calculate_advanced_risk(data)
        second = calculate_advanced_risk(data)

        self.assertEqual(first, second)

    def test_permission_combination_detection(self):
        data = self.make_app_data(
            requested=["CAMERA", "RECORD_AUDIO"],
            purpose="Video recording",
            category="Photography",
        )

        result = calculate_advanced_risk(data)

        findings = result["score_breakdown"]["permission_combinations"]["findings"]

        self.assertTrue(
            any(
                set(item["permissions"]) == {"CAMERA", "RECORD_AUDIO"}
                for item in findings
            )
        )

    def test_missing_purpose_is_reported(self):
        data = self.make_app_data(requested=["READ_CONTACTS"])

        result = calculate_advanced_risk(data)

        self.assertEqual(result["score_breakdown"]["purpose_mismatch"]["score"], 0)

        self.assertTrue(
            any("purpose" in item.lower() for item in result["limitations"])
        )

    def test_score_limits(self):
        data = self.make_app_data(
            requested=[
                "READ_SMS",
                "READ_CONTACTS",
                "CAMERA",
                "RECORD_AUDIO",
                "ACCESS_FINE_LOCATION",
                "READ_CALL_LOG",
                "ACCESS_BACKGROUND_LOCATION",
            ],
            granted=["READ_SMS", "READ_CONTACTS", "CAMERA", "RECORD_AUDIO"],
            purpose="Calculator",
            category="Utility",
        )

        result = calculate_advanced_risk(data)

        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

        breakdown = result["score_breakdown"]

        self.assertLessEqual(breakdown["permission_sensitivity"]["score"], 40)
        self.assertLessEqual(breakdown["permission_combinations"]["score"], 25)
        self.assertLessEqual(breakdown["purpose_mismatch"]["score"], 20)
        self.assertLessEqual(breakdown["granted_access_exposure"]["score"], 15)

    # Test actual risk classification boundaries
    def test_risk_level_thresholds(self):
        test_cases = [
            (0, "LOW"),
            (24, "LOW"),
            (25, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (74, "HIGH"),
            (75, "CRITICAL"),
            (100, "CRITICAL"),
        ]

        for score, expected_level in test_cases:
            with self.subTest(score=score):
                self.assertEqual(classify_risk_level(score), expected_level)


if __name__ == "__main__":
    unittest.main(verbosity=2)
