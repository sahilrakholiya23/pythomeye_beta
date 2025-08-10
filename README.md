# pythomeye_beta
pythomeye beta version


# 🛡 PhantomEye — AI-Powered Real-Time Honeypot & Intrusion Detection System

PhantomEye is an **AI-driven live cyber defense tool** that acts as a smart proxy between users and your real web application.  
It instantly detects suspicious requests (SQL Injection, XSS, directory traversal, bot scanning, etc.), sends **real-time email alerts**, and redirects attackers to a **fake honeypot** where their activity is logged — all without affecting legitimate users.

---

## 🚀 Features
- **Real-Time Attack Detection** — instantly scans requests for malicious patterns.
- **Honeypot Trap** — redirects attackers to a fake admin panel & logs their actions.
- **Instant Email Alerts** — sends immediate alerts when suspicious activity is detected.
- **Live Web Dashboard** — view attack logs & honeypot captures in real time.
- **Async Proxy Architecture** — high-performance request handling without delays.
- **Customizable Rules** — add or modify attack patterns using regex.

---

## 📂 Project Structure
phantomeye_demo_ui.py # Main application (proxy, backend, honeypot, dashboard)
attack_logs.txt # Logs of detected attacks
honeypot_logs.txt # Logs of honeypot activity
README.md # This file



## 🔧 Installation
1. **Clone the Repository**
```bash
git clone https://github.com/your-username/PhantomEye.git
cd PhantomEye
Install Dependencies
pip install flask
Set Environment Variables for Email Alerts
PhantomEye uses App Passwords for Gmail to send alerts securely.

```

📧 How to Get Your Gmail App Password
If you use Gmail for sending alerts, you must create an App Password (not your normal login password).

Go to Google Account Security.

Enable 2-Step Verification.

Scroll to "App passwords" section.

Choose:

App: Mail

Device: Other (Custom name) → Enter PhantomEye

Click Generate — Copy the 16-character password shown.

Example .env or environment variables:


export PHANTOM_EMAIL_USER="your-email@gmail.com"
export PHANTOM_EMAIL_PASS="your-16-character-app-password"
export PHANTOM_EMAIL_TO="destination-email@gmail.com"


▶️ Running PhantomEye

python phantomeye_demo_ui.py
🌐 Access the System
Main Site (Backend): http://127.0.0.1:8080

Honeypot Trap: Automatically redirects on attack detection

Dashboard: http://127.0.0.1:5001

🧪 Testing the System
✅ Safe Request
 http://127.0.0.1:8080/

🚨 SQL Injection Test
 "http://127.0.0.1:8080/?id=1' OR 1=1--"


🚨 XSS Test
"http://127.0.0.1:8080/"
📊 Dashboard Preview
The live dashboard shows:

Detected Attacks (marked SUSPICIOUS)

Honeypot Captures (fake login attempts)

System status (Proxy, Backend, Honeypot)

⚠️ Disclaimer
This project is for educational and security research purposes only.
Do not deploy in production without proper hardening.

👨‍💻 Author
[Sahil Rakholiya]
GitHub: mrsudo
