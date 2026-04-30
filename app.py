from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import mysql.connector
import hashlib

app = Flask(__name__)
app.secret_key = "cyberlens_secret_2026"

CYBERLENS_CODE = "Chocobar"

def get_db():
    return mysql.connector.connect(
        host="localhost",
        port=3308,
        user="root",
        password="Tejass@06",
        database="cyberlens"
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── AUTH ROUTES ──────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s",
                       (username, hash_password(password)))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user:
            session['user'] = username
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid username or password'})
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        confirm = data.get('confirm', '')
        code = data.get('code', '')
        if code != CYBERLENS_CODE:
            return jsonify({'success': False, 'error': 'Invalid CyberLens Code'})
        if password != confirm:
            return jsonify({'success': False, 'error': 'Passwords do not match'})
        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)",
                           (username, hash_password(password)))
            conn.commit()
            cursor.close()
            conn.close()
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': 'Username already taken'})
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ── MAIN ROUTES ──────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('user'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT i.incident_id, t.attack_type,
               s.level_name as severity,
               a.source_ip, sys.protocol,
               i.action_taken, i.status,
               i.anomaly_score, i.is_flagged,
               i.timestamp
        FROM incident i
        JOIN threat t ON i.threat_id = t.threat_id
        JOIN severity_level s ON t.severity_id = s.severity_id
        JOIN attacker a ON i.attacker_id = a.attacker_id
        JOIN affected_system sys ON i.system_id = sys.system_id
        WHERE t.attack_type LIKE %s
        LIMIT 50
    """, (f'%{query}%',))
    results = cursor.fetchall()
    for r in results:
        if r.get('timestamp'):
            r['timestamp'] = str(r['timestamp'])
    cursor.close()
    conn.close()
    return jsonify(results)

@app.route('/stats')
@login_required
def stats():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.attack_type, COUNT(*) as total,
               AVG(i.anomaly_score) as avg_score
        FROM incident i
        JOIN threat t ON i.threat_id = t.threat_id
        GROUP BY t.attack_type
        ORDER BY total DESC
        LIMIT 5
    """)
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/kpis')
@login_required
def kpis():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) as total FROM incident")
    total = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as flagged FROM incident WHERE is_flagged = TRUE")
    flagged = cursor.fetchone()['flagged']
    cursor.execute("""
        SELECT COUNT(*) as critical FROM incident i
        JOIN threat t ON i.threat_id = t.threat_id
        JOIN severity_level s ON t.severity_id = s.severity_id
        WHERE s.level_name = 'Critical'
    """)
    critical = cursor.fetchone()['critical']
    cursor.execute("SELECT COUNT(*) as resolved FROM incident WHERE status = 'Resolved'")
    resolved = cursor.fetchone()['resolved']
    cursor.close()
    conn.close()
    return jsonify({'total': total, 'flagged': flagged, 'critical': critical, 'resolved': resolved})

if __name__ == '__main__':
    import os
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)