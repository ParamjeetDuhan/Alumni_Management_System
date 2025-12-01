 🎓 Alumni Information System

A Django-based web application to manage and connect alumni of Hindusthan College of Engineering and Technology.

 📌 Overview

The Alumni Information System is a full-stack web application built to manage alumni data, job postings, event updates, and institute-wide announcements. It provides a secure and centralized platform for both alumni and administrative users to interact and share information.

---

 🚀 Features

- 🔐 Secure Login (Admin & Alumni)
- 📝 Alumni Registration with admin approval
- 👤 Profile Management with inline editing
- 💼 Job Postings by alumni & admin
- 📅 Event Management and announcements
- 📰 News Feed maintained by admin
- 📁 Alumni Directory with search filters
- 📧 Forgot Password via OTP verification
- 📊 Dashboard Stats (Alumni, Jobs, Events)

---

 🛠️ Tech Stack

| Layer        | Technology            |
|--------------|------------------------|
| Frontend       | HTML, CSS, JavaScript  |
| Backend       | Python, Django         |
| Database      | PostgreSQL             |
| Other Tools  | Django ORM, Email SMTP |

---

 🔧 Installation

```bash
 Clone the repo
git clone https://github.com/Ravinthra/Alumni-Information-System.git
cd alumni-information-system

 Create virtual environment
python -m venv env
source env/bin/activate   On Windows: env\Scripts\activate

 Install dependencies
pip install -r requirements.txt

 Set up PostgreSQL database and update settings.py

 Run migrations
python manage.py makemigrations
python manage.py migrate

 Create superuser
python manage.py createsuperuser

 Run the development server
python manage.py runserver
```

---

 📂 Project Structure

```bash
alumni_information_system/
├── alumni/                  App folder
│   ├── models.py            DB Models
│   ├── views.py             Application logic
│   ├── forms.py             Django Forms
│   ├── urls.py              URL routing
│   └── templates/           HTML Templates
├── static/                  CSS/JS/Images
├── manage.py
└── requirements.txt
```

---

 ✅ Testing Highlights

- Validations for email, password strength, date/time formats
- OTP flow for password recovery tested
- Admin permission flows verified
- Tested on multiple screen sizes

---

 📱 Future Enhancements

- 📲 Mobile App (Android/iOS)
- 💬 Real-time Messaging
- 🎥 Virtual Alumni Meet Support (Video Calls)
- 📊 Alumni Analytics Dashboard
- 🔐 Enhanced login (OTP, Biometric)
