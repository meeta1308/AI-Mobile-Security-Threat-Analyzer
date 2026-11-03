import unittest

from app import build_permission_intelligence


class PermissionIntelligenceTests(unittest.TestCase):

    def make_app_data(
        self,
        requested=None,
        granted=None,
        not_granted=None,
        purpose="",
        category="",
    ):
        return {
            "requested_permissions": requested or [],
            "granted_permissions": granted or [],
            "not_granted_permissions": not_granted or [],
            "app_purpose": purpose,
            "app_category": category,
        }

    def test_granted_permission_status(self):
        data = self.make_app_data(
            requested=["CAMERA"],
            granted=["CAMERA"],
        )

        result = build_permission_intelligence(data)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["grant_status"], "GRANTED")

    def test_not_granted_permission_status(self):
        data = self.make_app_data(
            requested=["CAMERA"],
            not_granted=["CAMERA"],
        )

        result = build_permission_intelligence(data)

        self.assertEqual(result[0]["grant_status"], "NOT_GRANTED")

    def test_unknown_permission_status(self):
        data = self.make_app_data(
            requested=["CAMERA"],
        )

        result = build_permission_intelligence(data)

        self.assertEqual(result[0]["grant_status"], "UNKNOWN")

    def test_sensitivity_levels(self):
        data = self.make_app_data(
            requested=["READ_SMS", "CAMERA", "INTERNET"],
        )

        result = build_permission_intelligence(data)
        sensitivity = {item["permission"]: item["sensitivity"] for item in result}

        self.assertEqual(sensitivity["READ_SMS"], "HIGH")
        self.assertEqual(sensitivity["CAMERA"], "MEDIUM")
        self.assertEqual(sensitivity["INTERNET"], "LOW")

    def test_purpose_relevance(self):
        data = self.make_app_data(
            requested=["CAMERA", "READ_CONTACTS"],
            purpose="Photography",
        )

        result = build_permission_intelligence(data)
        relevance = {item["permission"]: item["purpose_relevance"] for item in result}

        self.assertEqual(
            relevance["CAMERA"],
            "POSSIBLY_RELEVANT",
        )
        self.assertEqual(
            relevance["READ_CONTACTS"],
            "REVIEW_REQUIRED",
        )

    def test_missing_purpose(self):
        data = self.make_app_data(
            requested=["CAMERA"],
        )

        result = build_permission_intelligence(data)

        self.assertEqual(
            result[0]["purpose_relevance"],
            "NOT_EVALUATED",
        )

    def test_undocumented_permission(self):
        data = self.make_app_data(
            requested=["UNKNOWN_PERMISSION"],
        )

        result = build_permission_intelligence(data)

        self.assertEqual(result[0]["sensitivity"], "UNKNOWN")
        self.assertIn("not yet documented", result[0]["description"])

    def test_permission_metadata_fields(self):
        data = self.make_app_data(
            requested=["CAMERA"],
        )

        result = build_permission_intelligence(data)
        item = result[0]

        required_fields = [
            "permission",
            "description",
            "data_exposure",
            "sensitivity",
            "grant_status",
            "purpose_relevance",
        ]

        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, item)

    def test_empty_permissions(self):
        data = self.make_app_data()

        result = build_permission_intelligence(data)

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
