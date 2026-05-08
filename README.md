# DukaanOS — Decision Intelligence Platform 🛒📊

**DukaanOS** is a robust, security-first retail management system designed to provide store owners with "Decision Intelligence." It combines inventory management, real-time billing, and deep forensic analytics into a single, high-performance platform.

---

## 🌟 Key Features

### 🔐 Zero-Trust Security Architecture
*   **Dual-Channel MFA**: Multi-step registration requiring both Mobile and Email OTP verification.
*   **Brute-Force Protection**: Automatic IP and account throttling after multiple failed attempts.
*   **Forensic Visibility**: Every action (logins, stock changes, sales) is recorded in an immutable audit trail with IP and device tracking.
*   **Secure Sessions**: Uses 64-character opaque tokens with `HttpOnly` cookie protection to prevent XSS and session hijacking.

### 📦 Inventory & Stock v2
*   **Modular Schema**: Separates static product data (Items) from dynamic stock data (Quantity/Price) for accurate profit tracking.
*   **Bulk CSV Import**: Instantly upload thousands of products with intelligent duplicate detection and automated stock initialization.
*   **Low Stock Alerts**: Real-time monitoring with visual alerts for reordering.

### 💳 Fast Billing Terminal
*   **Dynamic UI**: Lightweight, responsive billing interface designed for high-speed checkout.
*   **Atomic Transactions**: Ensures database consistency—stock is only reduced if the payment and bill generation are successful.
*   **GST Compliance**: Automatic tax calculations based on category-wise GST percentages.

---

## 🚀 Tech Stack

| Layer | Technology |
| :--- | :--- |
| **Backend** | Python / Django 4.2 |
| **Database** | MySQL (Strict Mode) |
| **Frontend** | Vanilla JS, HTML5, CSS3 (Modern Flex/Grid) |
| **Visualization** | Chart.js |
| **APIs** | Fast2SMS, Twilio, Gmail SMTP |
| **Config** | Python-Decouple (Env Management) |

---

## 🛠️ Installation & Setup

### 1. Prerequisites
*   Python 3.10+
*   MySQL Server
*   Pip (Python Package Manager)

### 2. Clone & Install
```bash
git clone https://github.com/your-username/dukaanos_project.git
cd dukaanos_project
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the `.env.example` to `.env` and update your credentials:
```bash
cp .env.example .env
```
Update these fields in `.env`:
*   `DB_PASSWORD`: Your MySQL password.
*   `EMAIL_HOST_PASSWORD`: Your Gmail App Password.
*   `FAST2SMS_API_KEY`: Your Dev API Key from Fast2SMS.

### 4. Database Setup
Create the database and apply migrations:
```bash
python manage.py migrate
# (Optional) Import the v2 schema manually if required
# mysql -u root -p dukaanos < dukaanos_schema_v2.sql
```

### 5. Run the Server
```bash
python manage.py runserver
```
Visit `http://127.0.0.1:8000` to access the platform.

---

## 📂 Project Structure
```text
dukaanos_project/
├── auth_app/           # Core logic (Auth, Inventory, Billing)
│   ├── views/          # Modular API logic
│   ├── utils.py        # Security & 3rd party helpers
│   └── models.py       # DB Schema definitions
├── dukaanos/           # Project settings & root routing
├── templates/          # HTML interfaces
└── static/             # CSS, JS, and Images
```

---

## 🤝 Contribution
Contributions are welcome! Please fork the repo and submit a PR for any security enhancements or feature additions.

---

## 📜 License
This project is licensed under the MIT License. Developed for **Academic/Industry Review**.
