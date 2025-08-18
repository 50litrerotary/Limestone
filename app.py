from flask import Flask, render_template, request, redirect, url_for, flash
from livereload import Server
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, Text, ForeignKey, Table, DateTime
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = "super-secret-key"

# --- DB CONFIG ---
DATABASE_URI = "mysql://limestone_user:StrongLocalPass!23@localhost/limestone"
engine = create_engine(DATABASE_URI, pool_pre_ping=True, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

# --- MODELS ---

book_tags = Table(
    "book_tags",
    Base.metadata,
    Column("book_id", ForeignKey("books.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    books = relationship("Book", back_populates="owner", cascade="all, delete-orphan")
    tags = relationship("Tag", back_populates="owner", cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")

class Book(Base):
    __tablename__ = "books"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    title = Column(String(255), nullable=False)
    author = Column(String(255), nullable=True)
    genre = Column(String(100), nullable=True)

    cover_path = Column(String(500), nullable=True)
    file_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="books")
    notes = relationship("Note", back_populates="book", cascade="all, delete-orphan")
    progress = relationship("ReadingProgress", back_populates="book", uselist=False, cascade="all, delete-orphan")
    tags = relationship("Tag", secondary=book_tags, back_populates="books")

class ReadingProgress(Base):
    __tablename__ = "reading_progress"
    id = Column(Integer, primary_key=True)
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), unique=True, nullable=False)
    current_page = Column(Integer, default=0)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    book = relationship("Book", back_populates="progress")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name = Column(String(64), nullable=False)

    owner = relationship("User", back_populates="tags")
    books = relationship("Book", secondary=book_tags, back_populates="tags")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    book_id = Column(Integer, ForeignKey("books.id", ondelete="CASCADE"), index=True, nullable=False)

    page = Column(Integer, nullable=True)
    title = Column(String(255), nullable=True)
    text = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="notes")
    book = relationship("Book", back_populates="notes")
    highlights = relationship("Highlight", back_populates="note", cascade="all, delete-orphan")
    annotations = relationship("Annotation", back_populates="note", cascade="all, delete-orphan")

class Highlight(Base):
    __tablename__ = "highlights"
    id = Column(Integer, primary_key=True)
    note_id = Column(Integer, ForeignKey("notes.id", ondelete="CASCADE"), index=True, nullable=False)

    start = Column(Integer, nullable=False)
    end = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)

    note = relationship("Note", back_populates="highlights")

class Annotation(Base):
    __tablename__ = "annotations"
    id = Column(Integer, primary_key=True)
    note_id = Column(Integer, ForeignKey("notes.id", ondelete="CASCADE"), index=True, nullable=False)

    pos_x = Column(Integer, nullable=True)
    pos_y = Column(Integer, nullable=True)
    text = Column(Text, nullable=True)
    style = Column(String(20), nullable=True)

    note = relationship("Note", back_populates="annotations")

Base.metadata.create_all(bind=engine)

# --- HELPERS ---

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
            return redirect(url_for('bookshelf'), code=302)

        # Invalid creds -> show error on the same page
        flash("Invalid email or password", "error")
        return render_template('login.html', email=typed_email)

    # GET
    return render_template('login.html')

@app.route('/bookshelf')
def bookshelf():
    db = SessionLocal()

    authors = [row[0] for row in db.query(Book.author).distinct().all() if row[0]]
    genres  = [row[0] for row in db.query(Book.genre).distinct().all() if row[0]]
    tags    = [row[0] for row in db.query(Tag.name).distinct().all()]

    book_count = db.query(Book).count()

    selected_author = request.args.get('author', '')
    selected_genre  = request.args.get('genre', '')

    db.close()

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

        if not EMAIL_REGEX.match(email):
            email_error = "Please enter a valid email address (e.g., name@example.com)."
            has_errors = True

        if len(password) < 8:
            password_error = "Password must be at least 8 characters long."
            has_errors = True

        db = SessionLocal()

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

        hashed_pw = generate_password_hash(password)
        db.add(User(email=email, password_hash=hashed_pw))
        db.commit()
        db.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', email=email)

@app.route('/logout')
def logout():
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    server = Server(app.wsgi_app)
    server.serve(port=5001, debug=True)
