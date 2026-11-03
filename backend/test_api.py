import unittest
from unittest.mock import patch

import app


class ApiIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.client = app.app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_invalid_request_body(self):
        response = self.client.post("/analyze", json=["CAMERA"])

        self.assertEqual(response.status_code, 400)

    def test_invalid_permissions_type(self):
        response = self.client.post("/analyze", json={"permissions": "CAMERA"})

        self.assertEqual(response.status_code, 400)

    def test_ai_not_configured(self):
        with patch.object(app, "GEMINI_API_KEY", ""):
            response = self.client.post("/analyze", json={"permissions": ["CAMERA"]})

        self.assertEqual(response.status_code, 503)

    def test_successful_analysis_with_mocked_ai(self):
        fake_ai_result = {
            "summary": "Test security analysis.",
            "findings": [
                {
                    "permission": "CAMERA",
                    "severity": "LOW",
                    "reason": "Camera access was requested.",
                    "recommendation": "Review camera access.",
                }
            ],
            "recommendations": ["Review app permissions."],
            "limitations": [],
        }

        request_data = {
            "app_name": "Test Camera App",
            "package_name": "com.example.testcamera",
            "app_category": "Photography",
            "app_purpose": "Video recording",
            "permissions": ["CAMERA", "RECORD_AUDIO"],
            "granted_permissions": ["CAMERA"],
            "not_granted_permissions": ["RECORD_AUDIO"],
        }

        with patch.object(app, "GEMINI_API_KEY", "test-key"):
            with patch.object(
                app, "analyze_with_gemini", return_value=fake_ai_result
            ) as mocked_ai:

                response = self.client.post("/analyze", json=request_data)

        self.assertEqual(response.status_code, 200)

        result = response.get_json()

        self.assertEqual(result["analysis_type"], "gemini_ai")
        self.assertEqual(result["risk_engine_version"], "1.0")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertIn("score_breakdown", result)
        self.assertIn("risk_level", result)
        self.assertEqual(result["app_name"], "Test Camera App")
        # Permission Intelligence checks
        self.assertIn("permission_intelligence", result)

        permission_data = result["permission_intelligence"]

        self.assertEqual(len(permission_data), 2)

        permission_map = {item["permission"]: item for item in permission_data}

        self.assertEqual(
            permission_map["CAMERA"]["grant_status"],
            "GRANTED",
        )

        self.assertEqual(
            permission_map["RECORD_AUDIO"]["grant_status"],
            "NOT_GRANTED",
        )

        self.assertEqual(
            permission_map["CAMERA"]["sensitivity"],
            "MEDIUM",
        )

        self.assertEqual(
            permission_map["RECORD_AUDIO"]["sensitivity"],
            "HIGH",
        )

        self.assertIn(
            "description",
            permission_map["CAMERA"],
        )

        self.assertIn(
            "data_exposure",
            permission_map["CAMERA"],
        )

        mocked_ai.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
