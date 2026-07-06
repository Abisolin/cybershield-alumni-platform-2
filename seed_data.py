"""seed_data.py — Creates all tables and inserts sample users for all 3 roles."""
import sqlite3, hashlib, hmac, os, secrets
from datetime import datetime

DATABASE = 'alumni.db'

try:
    import bcrypt as _bcrypt
except ImportError:
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

def hash_password(pw, method):
    if method == 'bcrypt':
        salt = _bcrypt.gensalt(rounds=12)
        h    = _bcrypt.hashpw(pw.encode(), salt)
        return h.hex(), salt.hex()
    elif method == 'pbkdf2':
        salt = os.urandom(32)
        key  = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 310_000)
        return key.hex(), salt.hex()
    elif method == 'sha256':
        salt = secrets.token_hex(32)
        h    = hashlib.sha256((salt+pw).encode()).hexdigest()
        return h, salt

USERS = [
    # ADMIN 1 — existing
    {"role":"admin","student_id":"ADMIN001","full_name":"Dr. Rajesh Kumar","email":"admin@college.edu",
     "phone":"+91-9800000001","department":"Administration","graduation_year":None,"current_year":None,
     "degree":None,"company":"University","job_title":"System Administrator","location":"Campus",
     "linkedin":"","bio":"System administrator with full access.","password":"Admin@123!","method":"bcrypt"},

    # ADMIN 2 — Abisolin
    {"role":"admin","student_id":"ADMIN002","full_name":"Abisolin","email":"abiabisolin@gmail.com",
     "phone":"+91-9800000002","department":"Administration","graduation_year":None,"current_year":None,
     "degree":None,"company":"University","job_title":"System Administrator","location":"Campus",
     "linkedin":"","bio":"Admin access for Abisolin.","password":"12345Abi@","method":"bcrypt"},

    # ALUMNI
    {"role":"alumni","student_id":"CS2018001","full_name":"Aarav Sharma","email":"aarav.sharma@email.com",
     "phone":"+91-9876543210","department":"Computer Science","graduation_year":2018,"current_year":None,
     "degree":"B.Tech","company":"Google India","job_title":"Software Engineer III","location":"Bangalore",
     "linkedin":"linkedin.com/in/aaravsharma","bio":"Distributed systems & cloud computing.",
     "password":"Aarav@2018!","method":"bcrypt"},

    {"role":"alumni","student_id":"EC2019002","full_name":"Priya Nair","email":"priya.nair@email.com",
     "phone":"+91-9876543211","department":"Electronics","graduation_year":2019,"current_year":None,
     "degree":"B.Tech","company":"Infosys","job_title":"Senior Analyst","location":"Chennai",
     "linkedin":"linkedin.com/in/priyanair","bio":"IoT and embedded systems.",
     "password":"Priya@2019!","method":"pbkdf2"},

    {"role":"alumni","student_id":"CS2017003","full_name":"Sneha Reddy","email":"sneha.reddy@email.com",
     "phone":"+91-9876543212","department":"Computer Science","graduation_year":2017,"current_year":None,
     "degree":"M.Tech","company":"Microsoft","job_title":"Product Manager","location":"Hyderabad",
     "linkedin":"linkedin.com/in/snehareddy","bio":"AI/ML products & strategy.",
     "password":"Sneha@2017!","method":"sha256"},

    {"role":"alumni","student_id":"IT2020004","full_name":"Vikram Singh","email":"vikram.singh@email.com",
     "phone":"+91-9876543213","department":"IT","graduation_year":2020,"current_year":None,
     "degree":"B.Tech","company":"Amazon","job_title":"SDE-2","location":"Delhi",
     "linkedin":"linkedin.com/in/vikramsingh","bio":"Backend systems & AWS.",
     "password":"Vikram@2020!","method":"bcrypt"},

    {"role":"alumni","student_id":"ME2018005","full_name":"Kavya Menon","email":"kavya.menon@email.com",
     "phone":"+91-9876543214","department":"Mechanical","graduation_year":2018,"current_year":None,
     "degree":"B.Tech","company":"Tata Motors","job_title":"Design Engineer","location":"Pune",
     "linkedin":"linkedin.com/in/kavyamenon","bio":"EV powertrain design.",
     "password":"Kavya@2018!","method":"pbkdf2"},

    # STUDENTS
    {"role":"student","student_id":"CS2024101","full_name":"Arjun Patel","email":"arjun.patel@student.edu",
     "phone":"+91-9712345601","department":"Computer Science","graduation_year":None,"current_year":3,
     "degree":"B.Tech","company":None,"job_title":None,"location":"Campus",
     "linkedin":"","bio":"3rd year CSE. Interested in SDE roles.",
     "password":"Arjun@2024!","method":"bcrypt"},

    {"role":"student","student_id":"EC2024102","full_name":"Diya Joshi","email":"diya.joshi@student.edu",
     "phone":"+91-9712345602","department":"Electronics","graduation_year":None,"current_year":4,
     "degree":"B.Tech","company":None,"job_title":None,"location":"Campus",
     "linkedin":"","bio":"Final year ECE. Looking for embedded roles.",
     "password":"Diya@2024!","method":"pbkdf2"},

    {"role":"student","student_id":"IT2024103","full_name":"Rahul Gupta","email":"rahul.gupta@student.edu",
     "phone":"+91-9712345603","department":"IT","graduation_year":None,"current_year":2,
     "degree":"B.Tech","company":None,"job_title":None,"location":"Campus",
     "linkedin":"","bio":"2nd year IT. Web dev enthusiast.",
     "password":"Rahul@2024!","method":"sha256"},

    {"role":"student","student_id":"CS2024104","full_name":"Ananya Krishnan","email":"ananya.k@student.edu",
     "phone":"+91-9712345604","department":"Computer Science","graduation_year":None,"current_year":4,
     "degree":"B.Tech","company":None,"job_title":None,"location":"Campus",
     "linkedin":"","bio":"Final year. Data science & ML focus.",
     "password":"Ananya@2024!","method":"bcrypt"},
]

PLACEMENTS = [
    {"company":"Google India","job_title":"Software Engineer","job_type":"Full-Time","location":"Bangalore",
     "salary_range":"18-25 LPA","description":"Join Google India engineering team. Work on large-scale distributed systems serving millions of users worldwide.",
     "requirements":"B.Tech/M.Tech in CS or related. Strong DSA & system design. 0-2 years experience.",
     "apply_link":"https://www.linkedin.com/jobs/view/4403955615/","deadline":"2025-06-15","poster_email":"aarav.sharma@email.com"},

    {"company":"Microsoft","job_title":"Principal Software Engineer","job_type":"Full-Time","location":"Hyderabad",
     "salary_range":"35-50 LPA","description":"Lead engineering efforts on Microsoft Azure. Drive technical vision and mentor engineers across teams.",
     "requirements":"8+ years of software development experience. Expert in distributed systems. Strong leadership skills.",
     "apply_link":"https://www.linkedin.com/jobs/view/4406855857/","deadline":"2025-06-28","poster_email":"sneha.reddy@email.com"},

    {"company":"Infosys","job_title":"Senior Software Developer","job_type":"Full-Time","location":"Chennai",
     "salary_range":"8-12 LPA","description":"Senior developer role working on enterprise solutions for global clients across multiple domains.",
     "requirements":"3-5 years experience. Java/Python skills. Good communication and problem-solving.",
     "apply_link":"https://www.linkedin.com/jobs/view/4393089807/","deadline":"2025-07-01","poster_email":"priya.nair@email.com"},

    {"company":"Amazon","job_title":"SDE Intern","job_type":"Internship","location":"Bangalore",
     "salary_range":"60,000/month","description":"6-month internship. Work on live features in Amazon AppStore software excellence team.",
     "requirements":"3rd/4th year B.Tech CS/IT. Strong in OOP & DSA. Good problem-solving skills.",
     "apply_link":"https://www.linkedin.com/safety/go/?url=https%3A%2F%2Fwww%2Eamazon%2Ejobs%2Fjobs%2F10371338%2Fsystem-development-engineer-appstore-software-excellence%3Fcmpid%3DSPLICX0248M%26utm_source%3Dlinkedin%2Ecom%26utm_campaign%3Dcxro%26utm_medium%3Dsocial_media%26utm_content%3Djob_posting%26ss%3Dpaid&urlhash=AlnR&isSdui=true","deadline":"2025-05-30","poster_email":"vikram.singh@email.com"},

    {"company":"Tata Motors","job_title":"Software Engineer","job_type":"Full-Time","location":"Pune",
     "salary_range":"6-9 LPA","description":"Software Engineer at Tata Motors working on connected vehicle software and next-gen automotive systems.",
     "requirements":"B.Tech in CS/ECE. Knowledge of embedded systems or automotive software preferred.",
     "apply_link":"https://www.linkedin.com/jobs/view/4404814121/","deadline":"2025-06-20","poster_email":"kavya.menon@email.com"},
]

EVENTS = [
    {"title":"Annual Alumni Meet 2025","type":"Networking","date":"2025-03-15",
     "location":"University Auditorium","seats":500,
     "desc":"Grand annual reunion. Keynotes, networking, cultural evening.",
     "organizer_email":"aarav.sharma@email.com"},

    {"title":"Tech Talk: AI in Industry","type":"Seminar","date":"2025-02-20",
     "location":"Online (Zoom)","seats":200,
     "desc":"Panel of alumni working in AI/ML. Live Q&A included.",
     "organizer_email":"sneha.reddy@email.com"},

    {"title":"Mock Interview Drive","type":"Workshop","date":"2025-03-05",
     "location":"CSE Block Lab 3","seats":60,
     "desc":"Alumni-led mock interviews for final year students. 1-on-1 sessions.",
     "organizer_email":"vikram.singh@email.com"},

    {"title":"Startup Bootcamp","type":"Workshop","date":"2025-04-10",
     "location":"Innovation Hub","seats":80,
     "desc":"3-day intensive for aspiring founders. Covers funding, legal, GTM.",
     "organizer_email":"priya.nair@email.com"},
]

NEWS = [
    {"title":"Aarav Sharma Wins Google Innovation Award",
     "content":"Our alumnus Aarav Sharma (CS 2018) received the Google Innovation Award for his work on distributed caching. He credits the strong DSA foundation built at our college.",
     "category":"Achievement","author_email":"aarav.sharma@email.com"},

    {"title":"College Ranks #5 in NIRF 2024",
     "content":"Our institution secured #5 nationally in the NIRF 2024 rankings. The Engineering department saw a 2-spot jump driven by placement records and research output.",
     "category":"Announcement","author_email":"admin@college.edu"},

    {"title":"New Alumni Scholarship Fund Launched",
     "content":"The Alumni Association has launched a merit-cum-need scholarship funded entirely by alumni donations. Applications open for 2024-25 batch.",
     "category":"Announcement","author_email":"sneha.reddy@email.com"},

    {"title":"Campus Placement 2024 Breaks All Records",
     "content":"The 2024 placement season saw 94% placement with the highest ever package of 32 LPA offered by a leading MNC. Over 120 companies participated.",
     "category":"Placements","author_email":"admin@college.edu"},
]

def seed():
    conn = sqlite3.connect(DATABASE)
    # Create all tables
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL,
        student_id TEXT UNIQUE, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        phone TEXT, department TEXT, graduation_year INTEGER, current_year INTEGER,
        degree TEXT, company TEXT, job_title TEXT, location TEXT, linkedin TEXT, bio TEXT,
        password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
        hash_method TEXT NOT NULL DEFAULT 'bcrypt',
        is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT, login_attempts INTEGER DEFAULT 0, locked_until TEXT);
    CREATE TABLE IF NOT EXISTS placements (
        id INTEGER PRIMARY KEY AUTOINCREMENT, alumni_id INTEGER NOT NULL,
        company_name TEXT NOT NULL, job_title TEXT NOT NULL, job_type TEXT DEFAULT 'Full-Time',
        location TEXT, salary_range TEXT, description TEXT, requirements TEXT,
        apply_link TEXT, deadline TEXT, is_active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, organizer_id INTEGER NOT NULL,
        title TEXT NOT NULL, description TEXT, event_type TEXT DEFAULT 'Networking',
        event_date TEXT NOT NULL, location TEXT, max_seats INTEGER DEFAULT 100,
        is_active INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS event_registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, user_id INTEGER,
        registered_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS news (
        id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER NOT NULL,
        title TEXT NOT NULL, content TEXT NOT NULL, category TEXT DEFAULT 'General',
        published INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS placement_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, placement_id INTEGER, student_id INTEGER,
        cover_note TEXT, applied_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, role TEXT,
        action TEXT NOT NULL, ip_addr TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP);
    ''')
    conn.commit()
    # Clear
    for t in ['placement_applications','event_registrations','news','events','placements','audit_log','users']:
        conn.execute(f'DELETE FROM {t}')
    conn.commit()

    print("Seeding users...")
    for u in USERS:
        h, salt = hash_password(u['password'], u['method'])
        conn.execute('''INSERT INTO users(role,student_id,full_name,email,phone,department,
            graduation_year,current_year,degree,company,job_title,location,linkedin,bio,
            password_hash,password_salt,hash_method) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
            u['role'],u['student_id'],u['full_name'],u['email'],u['phone'],u['department'],
            u.get('graduation_year'),u.get('current_year'),u.get('degree'),u.get('company'),
            u.get('job_title'),u.get('location'),u.get('linkedin',''),u.get('bio',''),
            h, salt, u['method']))
        role_label = u['role'].upper().ljust(7)
        print(f"  ✓ [{role_label}] {u['full_name']:25} | {u['email']:35} / {u['password']} [{u['method'].upper()}]")
    conn.commit()

    # Get user id map
    uid_map = {row[0]:row[1] for row in conn.execute('SELECT email,id FROM users').fetchall()}

    print("\nSeeding placements...")
    for p in PLACEMENTS:
        aid = uid_map.get(p['poster_email'])
        if aid:
            conn.execute('''INSERT INTO placements(alumni_id,company_name,job_title,job_type,location,
                salary_range,description,requirements,apply_link,deadline) VALUES(?,?,?,?,?,?,?,?,?,?)''',
                (aid,p['company'],p['job_title'],p['job_type'],p['location'],p['salary_range'],
                 p['description'],p['requirements'],p['apply_link'],p['deadline']))
            print(f"  ✓ {p['company']} — {p['job_title']}")
    conn.commit()

    print("\nSeeding events...")
    for e in EVENTS:
        oid = uid_map.get(e['organizer_email'])
        if oid:
            conn.execute('''INSERT INTO events(organizer_id,title,description,event_type,event_date,location,max_seats)
                VALUES(?,?,?,?,?,?,?)''', (oid,e['title'],e['desc'],e['type'],e['date'],e['location'],e['seats']))
            print(f"  ✓ {e['title']}")
    conn.commit()

    print("\nSeeding news...")
    for n in NEWS:
        aid = uid_map.get(n['author_email'])
        if aid:
            conn.execute('INSERT INTO news(author_id,title,content,category) VALUES(?,?,?,?)',
                         (aid,n['title'],n['content'],n['category']))
            print(f"  ✓ {n['title']}")
    conn.commit()
    conn.close()

    print("\n" + "="*65)
    print("SEED COMPLETE!")
    print("="*65)
    print(f"\n{'ROLE':<10} {'EMAIL':<35} {'PASSWORD':<15} {'METHOD'}")
    print("-"*65)
    for u in USERS:
        print(f"{u['role'].upper():<10} {u['email']:<35} {u['password']:<15} {u['method'].upper()}")
    print("="*65)

if __name__ == '__main__':
    seed()