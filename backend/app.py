from flask import Flask, jsonify, request

app = Flask(__name__)

HIGH_RISK = {
    "READ_SMS": 25,
    "READ_CALL_LOG": 25,
    "ACCESS_FINE_LOCATION": 25,
    "RECORD_AUDIO": 25,
}
MEDIUM_RISK = {
    "CAMERA": 10,
    "READ_CONTACTS": 10,
    "READ_MEDIA_IMAGES": 10,
    "INTERNET": 10,
}

@app.get("/")
def home():
    return jsonify({
        "status": "success",
        "message": "AI Mobile Security Threat Analyzer backend is running"
    })

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

@app.post("/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    permissions = body.get("permissions", [])
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        return jsonify({"error": "'permissions' must be a list of strings"}), 400

    selected = list(dict.fromkeys(p.strip().upper() for p in permissions))
    score = 0
    findings = []

    for permission in selected:
        if permission in HIGH_RISK:
            score += HIGH_RISK[permission]
            findings.append({
                "permission": permission,
                "severity": "review",
                "message": "Check whether this sensitive access is necessary for the app's stated purpose."
            })
        elif permission in MEDIUM_RISK:
            score += MEDIUM_RISK[permission]
            findings.append({
                "permission": permission,
                "severity": "notice",
                "message": "Verify that this access is expected and clearly explained to the user."
            })
        else:
            findings.append({
                "permission": permission,
                "severity": "info",
                "message": "No rule is configured for this permission in the starter prototype."
            })

    score = min(score, 100)
    risk = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    return jsonify({
        "risk_score": score,
        "risk_level": risk,
        "permissions_analyzed": selected,
        "findings": findings,
        "disclaimer": "Permission indicators alone do not prove malicious behavior."
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
