from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Change this in production

# -----------------------------
# Database Setup
# -----------------------------
def get_db_connection():
    """Get a database connection with proper configuration"""
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrency
    conn.execute("PRAGMA journal_mode=WAL")
    # Set busy timeout to 5 seconds
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Call the database initializer when app starts
init_db()

# -----------------------------
# Database Helper Functions
# -----------------------------
def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    """Execute a database query with proper error handling and connection management"""
    max_retries = 3
    delay = 0.1
    
    for attempt in range(max_retries):
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            if params:
                cur.execute(query, params)
            else:
                cur.execute(query)
            
            if commit:
                conn.commit()
            
            if fetch_one:
                result = cur.fetchone()
            elif fetch_all:
                result = cur.fetchall()
            else:
                result = cur.lastrowid if query.strip().upper().startswith("INSERT") else None
            
            conn.close()
            return result
            
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e) and attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2  # Exponential backoff
                continue
            raise
        finally:
            if 'conn' in locals():
                conn.close()

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    try:
        user = execute_query(
            "SELECT * FROM users WHERE username=? AND role=?",
            (username, role),
            fetch_one=True
        )

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            if role == "Admin":
                return redirect(url_for("admin_portal"))
            elif role == "DA/CA":
                return redirect(url_for("da_portal"))
            elif role == "Defense":
                return redirect(url_for("defense_portal"))
            elif role == "LEGAL":
                return redirect(url_for("lea_portal"))
            else:
                flash("Invalid role selected")
                return redirect(url_for("index"))
        else:
            flash("Invalid credentials")
            return redirect(url_for("index"))
            
    except Exception as e:
        flash(f"An error occurred: {str(e)}")
        return redirect(url_for("index"))

@app.route("/signup", methods=["POST"])
def signup():
    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    try:
        hashed_password = generate_password_hash(password)
        
        # Check if username already exists
        existing_user = execute_query(
            "SELECT id FROM users WHERE username=?",
            (username,),
            fetch_one=True
        )
        
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("index"))
        
        # Insert new user
        execute_query(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role),
            commit=True
        )
        
        flash("Account created successfully. Please log in.")
        
    except sqlite3.IntegrityError:
        flash("Username already exists.")
    except Exception as e:
        flash(f"An error occurred: {str(e)}")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# -----------------------------
# Portal Routes
# -----------------------------
@app.route("/admin")
def admin_portal():
    if session.get("role") == "Admin":
        return render_template("admin-portal.html")
    return redirect(url_for("index"))

@app.route("/da")
def da_portal():
    if session.get("role") == "DA/CA":
        return render_template("da-portal.html")
    return redirect(url_for("index"))

@app.route("/defense")
def defense_portal():
    if session.get("role") == "Defense":
        return render_template("defense-portal.html")
    return redirect(url_for("index"))

@app.route("/lea")
def lea_portal():
    if session.get("role") == "LEGAL":
        return render_template("lea-portal.html")
    return redirect(url_for("index"))

# -----------------------------
# Context Processors
# -----------------------------
@app.context_processor
def inject_user():
    """Make user information available in all templates"""
    if 'username' in session:
        return {'user': {'username': session['username'], 'role': session['role']}}
    return {'user': None}

# -----------------------------
# Error Handlers
# -----------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# -----------------------------
# Teardown
# -----------------------------
@app.teardown_appcontext
def close_db_connection(exception=None):
    """Close database connection at the end of each request"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# -----------------------------
# Run App
# -----------------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
