from flask import Flask, render_template, request, redirect, session
import sqlite3
from collections import Counter
from datetime import datetime

app = Flask(__name__)
app.secret_key = "open_nids_secret"

DB_PATH = "database/nids.db"


# ---------------------------
# DB helper
# ---------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------
# Login (Admin & Analyst)
# ---------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT role FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()

        if user:
            # ---- SESSION ----
            session["user"] = username
            session["role"] = user["role"]

            # ---- ACTIVE USER INSERT (THIS IS THE PART YOU ASKED ABOUT) ----
            login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT OR REPLACE INTO active_users (username, role, login_time) VALUES (?, ?, ?)",
                (username, user["role"], login_time)
            )
            conn.commit()
            conn.close()

            # ---- REDIRECT BASED ON ROLE ----
            if user["role"] == "admin":
                return redirect("/admin/dashboard")
            else:
                return redirect("/analyst/dashboard")

        else:
            conn.close()
            error = "Invalid credentials"

    return render_template("auth/login.html", error=error)


# ---------------------------
# Analyst Dashboard
# ---------------------------
@app.route("/analyst/dashboard")
def analyst_dashboard():
    if session.get("role") != "analyst":
        return redirect("/")

    conn = get_db_connection()

    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()

    attack_types = Counter([a["alert_type"] for a in alerts])
    source_ips = Counter([a["src_ip"] for a in alerts])

    conn.close()

    return render_template(
        "analyst/dashboard.html",
        alerts=alerts,
        attack_types=attack_types,
        source_ips=source_ips
    )


# ---------------------------
# Admin Dashboard
# ---------------------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if session.get("role") != "admin":
        return redirect("/")

    conn = get_db_connection()

    alerts = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC"
    ).fetchall()

    users = conn.execute(
        "SELECT id, username, role FROM users"
    ).fetchall()

    active_users = conn.execute(
        "SELECT * FROM active_users"
    ).fetchall()

    conn.close()

    return render_template(
        "admin/dashboard.html",
        alerts=alerts,
        users=users,
        active_users=active_users,
        current_user=session.get("user")
    )


# ---------------------------
# Logout (remove from active_users)
# ---------------------------
@app.route("/logout")
def logout():
    username = session.get("user")

    if username:
        conn = get_db_connection()
        conn.execute(
            "DELETE FROM active_users WHERE username=?",
            (username,)
        )
        conn.commit()
        conn.close()

    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
