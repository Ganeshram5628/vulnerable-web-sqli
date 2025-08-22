# Python SQL Injection Lab

A simple intentionally vulnerable Python Flask web application for practicing **SQL Injection**.

## Features
- Vulnerable Login Page (`/`)
- Vulnerable Search Page (`/search`)
- SQLite Database Setup (`setup.sql`)

## Setup Instructions
1. Import `setup.sql` into SQLite:  
   ```bash
   sqlite3 vulndb.db < setup.sql
