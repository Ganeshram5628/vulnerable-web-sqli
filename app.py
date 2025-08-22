from flask import Flask, request
import sqlite3

app = Flask(__name__)

# Connect to SQLite database (for demo, you can switch to MySQL if needed)
def get_db():
    conn = sqlite3.connect("vulndb.db")
    conn.row_factory = sqlite3.Row
    return conn

# --------------------------
# Vulnerable Login
# --------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        cur = conn.cursor()
        # 🚨 Vulnerable query (string concatenation)
        query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{password}'"
        cur.execute(query)
        result = cur.fetchall()

        if result:
            return f"Login successful! Welcome, {user}"
        else:
            return "Invalid credentials"
    return '''
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <button type="submit" name="login">Login</button>
        </form>
    '''

# --------------------------
# Vulnerable Search
# --------------------------
@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    results_html = ""

    if q:
        conn = get_db()
        cur = conn.cursor()
        # 🚨 Vulnerable query
        query = f"SELECT * FROM users WHERE username LIKE '%{q}%'"
        cur.execute(query)
        rows = cur.fetchall()

        for row in rows:
            results_html += f"User: {row['username']}<br>"

    return f'''
        <form method="GET">
            Search Users: <input name="q"><br>
            <button type="submit">Search</button>
        </form>
        {results_html}
    '''

if __name__ == "__main__":
    app.run(debug=True)
