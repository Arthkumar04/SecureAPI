# 🛡️ SecureAPI – Intelligent API Security Gateway

**College Project – Live Working Model**

A complete, easy-to-understand API Security Gateway that demonstrates:

| Feature                      | Status |
|-----------------------------|--------|
| Authentication (JWT)        | ✅     |
| Authorization + RBAC        | ✅     |
| Input Validation            | ✅     |
| Parameter Validation        | ✅     |
| Rate Limiting               | ✅     |
| Suspicious Request Detection| ✅     |
| API Activity Logging        | ✅     |
| Secure Error Handling       | ✅     |

---

## 🚀 One-Click Setup (Windows)

1. **Unzip** the folder anywhere.
2. Double-click **`run.bat`**
3. Wait a few seconds (it installs dependencies the first time).
4. Open your browser → **http://127.0.0.1:8000/docs**

That’s it!

---

## 👤 Demo Accounts

| Username | Password  | Role  |
|----------|-----------|-------|
| `admin`  | `admin123`| admin |
| `alice`  | `alice123`| user  |
| `bob`    | `bob123`  | user  |

---

## 📖 How to Demo (Perfect for Viva / Presentation)

### 1. Open Swagger UI
Go to: http://127.0.0.1:8000/docs

### 2. Login
- Expand **POST /auth/login**
- Click **Try it out**
- Enter username & password (e.g. `alice` / `alice123`)
- Click **Execute**
- Copy the `access_token` value

### 3. Authorize
- Click the green **Authorize** button (top right)
- Paste the token
- Click Authorize → Close

### 4. Test Features

| What to show                     | How                                              |
|----------------------------------|--------------------------------------------------|
| **Authentication**               | Login works, token received                      |
| **RBAC (Authorization)**         | Login as `alice` → try `/api/admin/users` → 403 Forbidden<br>Login as `admin` → same endpoint works |
| **Input Validation**             | Call `/api/search` with `query: "union select"` → validation error |
| **Threat Detection**             | Call `/api/echo?q=union select * from users` → **Blocked** with threat score |
| **Rate Limiting**                | Spam any endpoint quickly → 429 Too Many Requests |
| **Activity Logging**             | Open `logs/api_activity.log` or watch the terminal |
| **Secure Errors**                | Bad requests never show stack traces             |

### 5. Nice Landing Page
http://127.0.0.1:8000/

---

## 🗂️ Project Structure

```
SecureAPI/
├── run.bat                 ← Double-click to start
├── requirements.txt
├── README.md
├── app/
│   ├── main.py             ← Main application + all endpoints
│   ├── auth.py             ← JWT + RBAC
│   ├── security.py         ← Rate limit, threat detection, logging
│   ├── models.py           ← Pydantic validation models
│   ├── config.py           ← Settings
│   └── __init__.py
└── logs/
    └── api_activity.log    ← Generated at runtime
```

---

## 🛠️ Manual Run (if needed)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## 🧪 Quick Test Ideas for Viva

1. **Normal flow**: Login → Get profile → Search data
2. **RBAC test**: User tries admin endpoint → blocked
3. **Attack simulation**:  
   - `GET /api/echo?q=../../../etc/passwd`  
   - `GET /api/echo?q=1' OR '1'='1`  
   → Gateway blocks with high threat score
4. **Rate limit**: Hit any endpoint 40 times quickly
5. Show the live log file

---

## 📌 Technologies Used

- **Python 3** + **FastAPI** (modern, auto documentation)
- **JWT** (JSON Web Tokens) for authentication
- **Pydantic** for strict input/parameter validation
- **slowapi** for rate limiting
- Custom **threat scoring engine**
- File-based activity logging
- Security headers on every response

---

## 💡 Why this project is good for college

- Fully working live model
- Easy to explain every feature
- Clean code with comments
- One-click setup
- Swagger UI makes demo impressive
- Shows real security concepts from syllabus

---

**Made for academic use – keep it simple, keep it clear.**
