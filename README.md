# PHP SQL Injection Lab

A simple intentionally vulnerable PHP web application for practicing **SQL Injection**.

## Features
- Vulnerable Login Page (`index.php`)
- Vulnerable Search Page (`search.php`)
- MySQL Database Setup (`setup.sql`)

## Setup Instructions
1. Import `setup.sql` into your MySQL server (phpMyAdmin or CLI).
2. Place project files inside `htdocs` (XAMPP) or your web root.
3. Start Apache + MySQL (via XAMPP/Docker/LAMP).
4. Access in browser:
   - `http://localhost/index.php` → Login
   - `http://localhost/search.php` → Search

## ⚠ Disclaimer
This project is **for educational purposes only**.
Do not deploy it on a production server.
