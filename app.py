"""
Alumni Management System v2
3 Roles: Admin | Alumni | Student
Security: bcrypt (native or shim), PBKDF2, SHA-256 + salting, lockout, audit
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3, hashlib, hmac, os, secrets
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=60)

DATABASE = 'alumni.db'

# ── bcrypt shim ──────────────────────────────────────────────────────────────
try:
    import bcrypt as _bcrypt
    _BCRYPT_NATIVE = True
except ImportError:
    _BCRYPT_NATIVE = False
    class _bcrypt:
        @staticmethod
        def gensalt(rounds=12):
            return (f"$2b${rounds}$").encode() + secrets.token_bytes(22)
        @staticmethod
        def hashpw(password: bytes, salt: bytes) -> bytes:
            try: rounds = int(salt.decode().split('$')[2])
            except: rounds = 12
            key = hashlib.pbkdf2_hmac('sha256', password, salt, 2**rounds)
            return salt + b'$' + key.hex().encode()
        @staticmethod
        def checkpw(password: bytes, hashed: bytes) -> bool:
            salt = hashed[:hashed.rfind(b'$')]
            return hmac.compare_digest(_bcrypt.hashpw(password, salt), hashed)

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            role            TEXT NOT NULL CHECK(role IN ('admin','alumni','student')),
            student_id      TEXT UNIQUE,
            full_name       TEXT NOT NULL,
            email           TEXT UNIQUE NOT NULL,
            phone           TEXT,
            department      TEXT,
            graduation_year INTEGER,
            current_year    INTEGER,
            degree          TEXT,
            company         TEXT,
            job_title       TEXT,
            location        TEXT,
            linkedin        TEXT,
            bio             TEXT,
            password_hash   TEXT NOT NULL,
            password_salt   TEXT NOT NULL,
            hash_method     TEXT NOT NULL DEFAULT 'bcrypt',
            is_active       INTEGER DEFAULT 1,
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login      TEXT,
            login_attempts  INTEGER DEFAULT 0,
            locked_until    TEXT
        );

        CREATE TABLE IF NOT EXISTS placements (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            alumni_id       INTEGER NOT NULL,
            company_name    TEXT NOT NULL,
            job_title       TEXT NOT NULL,
            job_type        TEXT DEFAULT 'Full-Time',
            location        TEXT,
            salary_range    TEXT,
            description     TEXT,
            requirements    TEXT,
            apply_link      TEXT,
            deadline        TEXT,
            is_active       INTEGER DEFAULT 1,
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(alumni_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            organizer_id    INTEGER NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            event_type      TEXT DEFAULT 'Networking',
            event_date      TEXT NOT NULL,
            location        TEXT,
            max_seats       INTEGER DEFAULT 100,
            is_active       INTEGER DEFAULT 1,
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(organizer_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS event_registrations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    INTEGER,
            user_id     INTEGER,
            registered_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS news (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id   INTEGER NOT NULL,
            title       TEXT NOT NULL,
            content     TEXT NOT NULL,
            category    TEXT DEFAULT 'General',
            published   INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(author_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS placement_applications (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            placement_id    INTEGER,
            student_id      INTEGER,
            cover_note      TEXT,
            applied_at      TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            role        TEXT,
            action      TEXT NOT NULL,
            ip_addr     TEXT,
            timestamp   TEXT DEFAULT CURRENT_TIMESTAMP
        );
        ''')

# ── Password Security ─────────────────────────────────────────────────────────
class Sec:
    @staticmethod
    def hash_bcrypt(pw):
        salt = _bcrypt.gensalt(rounds=12)
        h = _bcrypt.hashpw(pw.encode(), salt)
        return h.hex(), salt.hex()

    @staticmethod
    def verify_bcrypt(pw, stored_hash, salt_hex):
        try:
            salt = bytes.fromhex(salt_hex)
            stored = bytes.fromhex(stored_hash)
            return _bcrypt.checkpw(pw.encode(), stored)
        except: return False

    @staticmethod
    def hash_pbkdf2(pw):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 310_000)
        return key.hex(), salt.hex()

    @staticmethod
    def verify_pbkdf2(pw, stored_hash, salt_hex):
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 310_000)
        return hmac.compare_digest(key.hex(), stored_hash)

    @staticmethod
    def hash_sha256(pw):
        salt = secrets.token_hex(32)
        h = hashlib.sha256((salt + pw).encode()).hexdigest()
        return h, salt

    @staticmethod
    def verify_sha256(pw, stored_hash, salt):
        h = hashlib.sha256((salt + pw).encode()).hexdigest()
        return hmac.compare_digest(h, stored_hash)

    @classmethod
    def hash(cls, pw, method='bcrypt'):
        if method == 'bcrypt':   return cls.hash_bcrypt(pw) + ('bcrypt',)
        if method == 'pbkdf2':   h,s = cls.hash_pbkdf2(pw); return h,s,'pbkdf2'
        if method == 'sha256':   h,s = cls.hash_sha256(pw); return h,s,'sha256'
        raise ValueError(method)

    @classmethod
    def verify(cls, pw, h, s, method):
        if method == 'bcrypt':  return cls.verify_bcrypt(pw, h, s)
        if method == 'pbkdf2': return cls.verify_pbkdf2(pw, h, s)
        if method == 'sha256': return cls.verify_sha256(pw, h, s)
        return False

def pw_strength(pw):
    c = {'length':len(pw)>=8,'upper':any(x.isupper() for x in pw),
         'lower':any(x.islower() for x in pw),'digit':any(x.isdigit() for x in pw),
         'special':any(x in '!@#$%^&*()_+-=[]{}|;:,.<>?' for x in pw)}
    score = sum(c.values())
    return {'checks':c,'score':score,'valid':score>=4,
            'label':['Very Weak','Weak','Fair','Strong','Very Strong'][min(score-1,4)] if score else 'Very Weak'}

def log(user_id, role, action):
    with get_db() as db:
        db.execute('INSERT INTO audit_log(user_id,role,action,ip_addr) VALUES(?,?,?,?)',
                   (user_id, role, action, request.remote_addr))

# ── Auth decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrap(*a,**k):
        if 'user_id' not in session:
            flash('Please log in first.','warning')
            return redirect(url_for('login'))
        return f(*a,**k)
    return wrap

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrap(*a,**k):
            if session.get('role') not in roles:
                flash('Access denied.','danger')
                return redirect(url_for('dashboard'))
            return f(*a,**k)
        return wrap
    return decorator

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    db = get_db()
    stats = {
        'alumni':   db.execute("SELECT COUNT(*) FROM users WHERE role='alumni' AND is_active=1").fetchone()[0],
        'students': db.execute("SELECT COUNT(*) FROM users WHERE role='student' AND is_active=1").fetchone()[0],
        'placements': db.execute("SELECT COUNT(*) FROM placements WHERE is_active=1").fetchone()[0],
        'events':   db.execute("SELECT COUNT(*) FROM events WHERE is_active=1").fetchone()[0],
    }
    return render_template('index.html', stats=stats)


@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email','').strip()
        password = request.form.get('password','')
        role_sel = request.form.get('role','')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=? AND role=?',(email,role_sel)).fetchone()
        if not user:
            flash('Invalid credentials or wrong role selected.','danger')
            return render_template('login.html')
        # lockout check
        if user['locked_until']:
            lu = datetime.strptime(user['locked_until'],'%Y-%m-%d %H:%M:%S')
            if datetime.now() < lu:
                mins = int((lu-datetime.now()).total_seconds()//60)+1
                flash(f'Account locked. Try again in {mins} min.','danger')
                return render_template('login.html')
        if not user['is_active']:
            flash('Account deactivated. Contact admin.','danger')
            return render_template('login.html')
        if Sec.verify(password, user['password_hash'], user['password_salt'], user['hash_method']):
            with db:
                db.execute('UPDATE users SET last_login=?,login_attempts=0,locked_until=NULL WHERE id=?',
                           (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
            session.permanent = True
            session['user_id']   = user['id']
            session['role']      = user['role']
            session['full_name'] = user['full_name']
            session['hash_method'] = user['hash_method']
            log(user['id'], user['role'], 'LOGIN')
            flash(f'Welcome, {user["full_name"]}!','success')
            return redirect(url_for('dashboard'))
        else:
            attempts = (user['login_attempts'] or 0)+1
            locked_until = None
            if attempts >= 5:
                locked_until = (datetime.now()+timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
                flash('5 failed attempts. Account locked 15 min.','danger')
            else:
                flash(f'Wrong password. {5-attempts} attempts left.','danger')
            with db:
                db.execute('UPDATE users SET login_attempts=?,locked_until=? WHERE id=?',
                           (attempts,locked_until,user['id']))
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        f = request.form
        role   = f.get('role','student')
        pw     = f.get('password','')
        method = f.get('hash_method','bcrypt')
        # Block admin registration — admins are pre-configured only
        if role == 'admin':
            flash('Admin accounts cannot be registered. Contact the system administrator.','danger')
            return render_template('register.html', form=f)
        s = pw_strength(pw)
        if not s['valid']:
            flash('Password too weak (need 4/5 criteria).','danger')
            return render_template('register.html', form=f)
        if pw != f.get('confirm_password',''):
            flash('Passwords do not match.','danger')
            return render_template('register.html', form=f)
        db = get_db()
        if db.execute('SELECT id FROM users WHERE email=?',(f['email'],)).fetchone():
            flash('Email already registered.','danger')
            return render_template('register.html', form=f)
        h, salt, method_used = Sec.hash(pw, method)
        try:
            with db:
                db.execute('''INSERT INTO users
                    (role,student_id,full_name,email,phone,department,graduation_year,
                     current_year,degree,company,job_title,location,linkedin,bio,
                     password_hash,password_salt,hash_method)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
                    role, f.get('student_id'), f['full_name'], f['email'],
                    f.get('phone'), f.get('department'), f.get('graduation_year'),
                    f.get('current_year'), f.get('degree'), f.get('company'),
                    f.get('job_title'), f.get('location'), f.get('linkedin'),
                    f.get('bio'), h, salt, method_used))
            flash(f'Registered! Password secured with {method_used.upper()}.','success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {e}','danger')
    return render_template('register.html', form={})


@app.route('/logout')
@login_required
def logout():
    log(session['user_id'], session['role'], 'LOGOUT')
    session.clear()
    flash('Logged out successfully.','info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    db  = get_db()
    uid = session['user_id']
    role= session['role']
    user= db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()

    if role == 'admin':
        stats = {
            'total_users': db.execute('SELECT COUNT(*) FROM users WHERE is_active=1').fetchone()[0],
            'alumni':      db.execute("SELECT COUNT(*) FROM users WHERE role='alumni' AND is_active=1").fetchone()[0],
            'students':    db.execute("SELECT COUNT(*) FROM users WHERE role='student' AND is_active=1").fetchone()[0],
            'placements':  db.execute('SELECT COUNT(*) FROM placements').fetchone()[0],
            'events':      db.execute('SELECT COUNT(*) FROM events').fetchone()[0],
            'news':        db.execute('SELECT COUNT(*) FROM news').fetchone()[0],
        }
        recent_users = db.execute('SELECT * FROM users ORDER BY created_at DESC LIMIT 8').fetchall()
        recent_placements = db.execute('''SELECT p.*,u.full_name as poster FROM placements p
            JOIN users u ON p.alumni_id=u.id ORDER BY p.created_at DESC LIMIT 5''').fetchall()
        recent_logs = db.execute('''SELECT al.*,u.full_name FROM audit_log al
            LEFT JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 10''').fetchall()
        return render_template('admin_dashboard.html', user=user, stats=stats,
                               recent_users=recent_users, recent_placements=recent_placements,
                               recent_logs=recent_logs)

    elif role == 'alumni':
        my_placements = db.execute('SELECT * FROM placements WHERE alumni_id=? ORDER BY created_at DESC',(uid,)).fetchall()
        my_events     = db.execute('SELECT * FROM events WHERE organizer_id=? ORDER BY event_date DESC',(uid,)).fetchall()
        my_news       = db.execute('SELECT * FROM news WHERE author_id=? ORDER BY created_at DESC LIMIT 5',(uid,)).fetchall()
        stats = {
            'placements': len(my_placements),
            'events':     len(my_events),
            'news':       len(my_news),
            'applications': db.execute('''SELECT COUNT(*) FROM placement_applications pa
                JOIN placements p ON pa.placement_id=p.id WHERE p.alumni_id=?''',(uid,)).fetchone()[0],
        }
        return render_template('alumni_dashboard.html', user=user, stats=stats,
                               my_placements=my_placements, my_events=my_events, my_news=my_news)

    else:  # student
        placements = db.execute('''SELECT p.*,u.full_name as poster,u.company as poster_co
            FROM placements p JOIN users u ON p.alumni_id=u.id
            WHERE p.is_active=1 ORDER BY p.created_at DESC''').fetchall()
        events = db.execute('''SELECT e.*,u.full_name as organizer
            FROM events e JOIN users u ON e.organizer_id=u.id
            WHERE e.is_active=1 ORDER BY e.event_date DESC LIMIT 6''').fetchall()
        news   = db.execute('''SELECT n.*,u.full_name as author FROM news n
            JOIN users u ON n.author_id=u.id WHERE n.published=1
            ORDER BY n.created_at DESC LIMIT 4''').fetchall()
        applied_ids = [r[0] for r in db.execute(
            'SELECT placement_id FROM placement_applications WHERE student_id=?',(uid,)).fetchall()]
        registered_event_ids = [r[0] for r in db.execute(
            'SELECT event_id FROM event_registrations WHERE user_id=?',(uid,)).fetchall()]
        return render_template('student_dashboard.html', user=user,
                               placements=placements, events=events, news=news,
                               applied_ids=applied_ids, registered_event_ids=registered_event_ids)


# ── Alumni: Post Placement ────────────────────────────────────────────────────
@app.route('/placement/add', methods=['GET','POST'])
@login_required
@role_required('alumni','admin')
def add_placement():
    if request.method == 'POST':
        f = request.form
        uid = session['user_id']
        with get_db() as db:
            db.execute('''INSERT INTO placements
                (alumni_id,company_name,job_title,job_type,location,salary_range,
                 description,requirements,apply_link,deadline)
                VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                uid, f['company_name'], f['job_title'], f.get('job_type','Full-Time'),
                f.get('location'), f.get('salary_range'), f.get('description'),
                f.get('requirements'), f.get('apply_link'), f.get('deadline')))
        log(uid, session['role'], f"POST_PLACEMENT:{f['company_name']}")
        flash('Placement opportunity posted successfully!','success')
        return redirect(url_for('dashboard'))
    return render_template('add_placement.html')


@app.route('/placement/<int:pid>/delete', methods=['POST'])
@login_required
def delete_placement(pid):
    db = get_db()
    p = db.execute('SELECT * FROM placements WHERE id=?',(pid,)).fetchone()
    if p and (session['role']=='admin' or p['alumni_id']==session['user_id']):
        with db: db.execute('DELETE FROM placements WHERE id=?',(pid,))
        flash('Placement deleted.','info')
    return redirect(url_for('dashboard'))


# ── Student: Apply for Placement ──────────────────────────────────────────────
@app.route('/placement/<int:pid>/apply', methods=['POST'])
@login_required
@role_required('student')
def apply_placement(pid):
    db  = get_db()
    uid = session['user_id']
    already = db.execute(
        'SELECT id FROM placement_applications WHERE placement_id=? AND student_id=?',
        (pid, uid)).fetchone()
    if not already:
        note = request.form.get('cover_note', 'Applied via external link')
        with db:
            db.execute(
                'INSERT INTO placement_applications(placement_id,student_id,cover_note) VALUES(?,?,?)',
                (pid, uid, note))
        log(uid, 'student', f'APPLY_PLACEMENT:{pid}')
        flash('Application submitted successfully!', 'success')
    else:
        flash('You have already applied for this position.', 'info')
    return redirect(url_for('dashboard'))


# ── Alumni: Post Event ────────────────────────────────────────────────────────
@app.route('/event/add', methods=['GET','POST'])
@login_required
@role_required('alumni','admin')
def add_event():
    if request.method == 'POST':
        f   = request.form
        uid = session['user_id']
        with get_db() as db:
            db.execute('''INSERT INTO events
                (organizer_id,title,description,event_type,event_date,location,max_seats)
                VALUES(?,?,?,?,?,?,?)''', (
                uid, f['title'], f.get('description'), f.get('event_type','Networking'),
                f['event_date'], f.get('location'), f.get('max_seats',100)))
        log(uid, session['role'], f"POST_EVENT:{f['title']}")
        flash('Event posted!','success')
        return redirect(url_for('dashboard'))
    return render_template('add_event.html')


# ── Student: Register for Event ───────────────────────────────────────────────
@app.route('/event/<int:eid>/register', methods=['POST'])
@login_required
def register_event(eid):
    db  = get_db()
    uid = session['user_id']
    if db.execute('SELECT id FROM event_registrations WHERE event_id=? AND user_id=?',(eid,uid)).fetchone():
        flash('Already registered.','info')
    else:
        with db: db.execute('INSERT INTO event_registrations(event_id,user_id) VALUES(?,?)',(eid,uid))
        flash('Registered for event!','success')
    return redirect(url_for('dashboard'))


# ── Alumni: Post News ─────────────────────────────────────────────────────────
@app.route('/news/add', methods=['GET','POST'])
@login_required
@role_required('alumni','admin')
def add_news():
    if request.method == 'POST':
        f   = request.form
        uid = session['user_id']
        with get_db() as db:
            db.execute('INSERT INTO news(author_id,title,content,category) VALUES(?,?,?,?)',
                       (uid, f['title'], f['content'], f.get('category','General')))
        log(uid, session['role'], f"POST_NEWS:{f['title']}")
        flash('News published!','success')
        return redirect(url_for('dashboard'))
    return render_template('add_news.html')


# ── Profile ───────────────────────────────────────────────────────────────────
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    db  = get_db()
    uid = session['user_id']
    if request.method == 'POST':
        f = request.form
        with db:
            db.execute('''UPDATE users SET phone=?,department=?,company=?,job_title=?,
                location=?,linkedin=?,bio=? WHERE id=?''',
                (f.get('phone'),f.get('department'),f.get('company'),
                 f.get('job_title'),f.get('location'),f.get('linkedin'),f.get('bio'),uid))
        log(uid,session['role'],'PROFILE_UPDATE')
        flash('Profile updated!','success')
    user = db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    return render_template('profile.html', user=user)


# ── Change Password ───────────────────────────────────────────────────────────
@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        f   = request.form
        db  = get_db()
        uid = session['user_id']
        user= db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not Sec.verify(f['current_password'],user['password_hash'],user['password_salt'],user['hash_method']):
            flash('Current password incorrect.','danger')
            return render_template('change_password.html')
        if f['new_password'] != f['confirm_password']:
            flash('New passwords do not match.','danger')
            return render_template('change_password.html')
        s = pw_strength(f['new_password'])
        if not s['valid']:
            flash('New password too weak.','danger')
            return render_template('change_password.html')
        method = f.get('hash_method','bcrypt')
        h, salt, m = Sec.hash(f['new_password'], method)
        with db: db.execute('UPDATE users SET password_hash=?,password_salt=?,hash_method=? WHERE id=?',(h,salt,m,uid))
        session['hash_method'] = m
        log(uid,session['role'],f'PASSWORD_CHANGE:{m}')
        flash(f'Password updated using {m.upper()}!','success')
        return redirect(url_for('profile'))
    return render_template('change_password.html')


# ── Admin: Full User Management ───────────────────────────────────────────────
@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    db = get_db()
    role_filter = request.args.get('role','')
    q = 'SELECT * FROM users'
    params = []
    if role_filter:
        q += ' WHERE role=?'; params.append(role_filter)
    q += ' ORDER BY created_at DESC'
    users = db.execute(q, params).fetchall()
    return render_template('admin_users.html', users=users, role_filter=role_filter)


@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@login_required
@role_required('admin')
def toggle_user(uid):
    db = get_db()
    u  = db.execute('SELECT is_active FROM users WHERE id=?',(uid,)).fetchone()
    with db: db.execute('UPDATE users SET is_active=? WHERE id=?',(0 if u['is_active'] else 1, uid))
    flash('User status updated.','success')
    return redirect(url_for('admin_users'))


@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(uid):
    if uid == session['user_id']:
        flash("Can't delete yourself.",'danger')
        return redirect(url_for('admin_users'))
    with get_db() as db:
        db.execute('DELETE FROM users WHERE id=?',(uid,))
    flash('User deleted.','success')
    return redirect(url_for('admin_users'))


@app.route('/admin/placements')
@login_required
@role_required('admin')
def admin_placements():
    db = get_db()
    placements = db.execute('''SELECT p.*,u.full_name as poster FROM placements p
        JOIN users u ON p.alumni_id=u.id ORDER BY p.created_at DESC''').fetchall()
    return render_template('admin_placements.html', placements=placements)


@app.route('/admin/events')
@login_required
@role_required('admin')
def admin_events():
    db = get_db()
    events = db.execute('''SELECT e.*,u.full_name as organizer FROM events e
        JOIN users u ON e.organizer_id=u.id ORDER BY e.created_at DESC''').fetchall()
    return render_template('admin_events.html', events=events)


@app.route('/admin/logs')
@login_required
@role_required('admin')
def admin_logs():
    db = get_db()
    logs = db.execute('''SELECT al.*,u.full_name,u.role as urole FROM audit_log al
        LEFT JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 200''').fetchall()
    return render_template('admin_logs.html', logs=logs)


@app.route('/admin/applications')
@login_required
@role_required('admin')
def admin_applications():
    db = get_db()
    apps = db.execute('''SELECT pa.*,u.full_name as student_name,u.email as student_email,
        p.company_name,p.job_title,a.full_name as alumni_name
        FROM placement_applications pa
        JOIN users u ON pa.student_id=u.id
        JOIN placements p ON pa.placement_id=p.id
        JOIN users a ON p.alumni_id=a.id
        ORDER BY pa.applied_at DESC''').fetchall()
    return render_template('admin_applications.html', apps=apps)


# ── Placements browse ─────────────────────────────────────────────────────────
@app.route('/placements')
@login_required
def placements():
    db = get_db()
    search  = request.args.get('search','')
    jtype   = request.args.get('type','')
    q = '''SELECT p.*,u.full_name as poster FROM placements p
           JOIN users u ON p.alumni_id=u.id WHERE p.is_active=1'''
    params = []
    if search:
        q += ' AND (p.company_name LIKE ? OR p.job_title LIKE ? OR p.location LIKE ?)'
        params += [f'%{search}%']*3
    if jtype:
        q += ' AND p.job_type=?'; params.append(jtype)
    q += ' ORDER BY p.created_at DESC'
    rows = db.execute(q, params).fetchall()
    applied_ids = []
    if session['role'] == 'student':
        applied_ids = [r[0] for r in db.execute(
            'SELECT placement_id FROM placement_applications WHERE student_id=?',(session['user_id'],)).fetchall()]
    return render_template('placements.html', placements=rows, applied_ids=applied_ids,
                           search=search, jtype=jtype)


# ── Events browse ─────────────────────────────────────────────────────────────
@app.route('/events')
@login_required
def events():
    db = get_db()
    rows = db.execute('''SELECT e.*,u.full_name as organizer FROM events e
        JOIN users u ON e.organizer_id=u.id WHERE e.is_active=1
        ORDER BY e.event_date DESC''').fetchall()
    reg_ids = [r[0] for r in db.execute(
        'SELECT event_id FROM event_registrations WHERE user_id=?',(session['user_id'],)).fetchall()]
    return render_template('events.html', events=rows, reg_ids=reg_ids)


# ── News browse ───────────────────────────────────────────────────────────────
@app.route('/news')
@login_required
def news():
    db   = get_db()
    rows = db.execute('''SELECT n.*,u.full_name as author FROM news n
        JOIN users u ON n.author_id=u.id WHERE n.published=1
        ORDER BY n.created_at DESC''').fetchall()
    return render_template('news.html', articles=rows)


# ── API ───────────────────────────────────────────────────────────────────────
@app.route('/api/pw-strength', methods=['POST'])
def api_pw_strength():
    return jsonify(pw_strength(request.json.get('password','')))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
# jsonify already imported above via flask