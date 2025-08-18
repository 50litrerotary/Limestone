from flask import Flask, render_template, request, redirect, url_for, flash
from livereload import Server
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
import re

app = Flask(__name__)
app.secret_key = "super-secret-key"  # change in production

# --- DB CONFIG ---
DATABASE_URI = "mysql://limestone_user:StrongLocalPass!23@localhost/limestone"
engine = create_engine(DATABASE_URI, pool_pre_ping=True, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

# --- USER MODEL ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

Base.metadata.create_all(bind=engine)

# --- HELPERS ---
# Require <local>@<domain>.<tld> with TLD >= 2 letters; supports multi-level domains.
EMAIL_REGEX = re.compile(
    r"^(?=.{1,254}$)(?=.{1,64}@)[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$"
)

@app.teardown_appcontext
def remove_session(exception=None):
    SessionLocal.remove()

# --- ROUTES ---

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        typed_email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Reject bad email early
        if not EMAIL_REGEX.match(typed_email):
            flash("Please enter a valid email address (e.g., name@example.com).", "error")
            return render_template('login.html', email=typed_email)

        db = SessionLocal()
        user = db.query(User).filter_by(email=typed_email).first()
        ok = bool(user and check_password_hash(user.password_hash, password))
        db.close()

        if ok:
            # Successful login -> go to bookshelf
            return redirect(url_for('bookshelf'), code=302)

        # Invalid creds -> show error on the same page
        flash("Invalid email or password", "error")
        return render_template('login.html', email=typed_email)

    # GET
    return render_template('login.html')

@app.route('/bookshelf')
def bookshelf():
    selected_author = request.args.get('author', '')
    selected_genre = request.args.get('genre', '')

    # placeholders until DB wiring
    authors = []    # e.g. ["Ethan Mollick", "Kevin Horsley"]
    genres = []     # e.g. ["Psychology", "Business"]
    tags = []       # e.g. ["Science", "School"]
    book_count = 0

    return render_template(
        'bookshelf.html',
        authors=authors,
        genres=genres,
        tags=tags,
        selected_author=selected_author,
        selected_genre=selected_genre,
        book_count=book_count
    )

@app.route('/register', methods=['GET', 'POST'])
def register():
    email = ""
    email_error = ""
    password_error = ""

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        has_errors = False

        # Email format
        if not EMAIL_REGEX.match(email):
            email_error = "Please enter a valid email address (e.g., name@example.com)."
            has_errors = True

        # Password length
        if len(password) < 8:
            password_error = "Password must be at least 8 characters long."
            has_errors = True

        db = SessionLocal()

        # Duplicate email
        if not has_errors and db.query(User).filter_by(email=email).first():
            email_error = "Email already registered."
            has_errors = True

        if has_errors:
            db.close()
            return render_template(
                'register.html',
                email=email,
                email_error=email_error,
                password_error=password_error
            )

        # Create user
        hashed_pw = generate_password_hash(password)
        db.add(User(email=email, password_hash=hashed_pw))
        db.commit()
        db.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    # GET
    return render_template('register.html', email=email)

# --- NEW: Logout route (wire your Logout button to this) ---
@app.route('/logout')
def logout():
    # For now, just redirect back to login with a message
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# --- DEV SERVER ---
if __name__ == '__main__':
    server = Server(app.wsgi_app)
    server.serve(port=5001, debug=True)
