# AI Mobile Security Threat Analyzer — Starter

## Is starter mein kya hai?
- Kotlin Android app ka basic permission-risk analyzer
- Flask backend (`/health` aur `/analyze`)
- GitHub Actions workflow jo cloud mein debug APK build karta hai

## Abhi kaunsa feature kaam karta hai?
Android app mein user permissions select karke basic risk score aur findings dekh sakta hai. Ye initial prototype hai; ye phone ki doosri apps ko automatically scan nahi karta aur na hi malware ka final verdict deta hai.

## Windows / D drive par use karna
1. ZIP ko extract karke project ko `D:\mobile-security-threat-analyzer` mein rakho.
2. VS Code mein us folder ko open karo.
3. Android APK banane ke liye poora folder GitHub repository mein push karna hoga; `.github/workflows/android-apk.yml` cloud build karega.
4. GitHub repository mein `Actions` tab kholo, workflow run hone do, phir successful run ke `Artifacts` section se `app-debug` download karo.
5. APK ko apne Android phone par transfer karke install karo. Android par unknown-source install prompt aa sakta hai.

## Backend (Flask)
Backend folder mein:
```powershell
cd D:\mobile-security-threat-analyzer\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```
Local test: `http://127.0.0.1:5000/health`

Online host karne ke liye GitHub par repository push karke Render jaise Python web host par `backend` folder/root directory set karo:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Root directory: `backend`
- Environment: Python

Abhi Android app offline/local analysis karta hai. Backend ko online deploy karne ke baad agle step mein app ko backend URL se connect karenge. API key abhi add mat karna; agar future mein AI provider use kiya, key sirf server-side environment variable mein rahegi.

## Cloud APK build note
GitHub Actions workflow cloud runner par JDK 17, Android SDK aur Gradle setup karta hai. Isliye local machine par abhi Android Studio/JDK/SDK install karna zaroori nahi hai. APK workflow `app-debug.apk` banata hai, production/release signing nahi.
