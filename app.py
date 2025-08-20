from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from livereload import Server
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, ForeignKey, Table, DateTime
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = "super-secret-key"

# ---- File uploads ----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_COVER = {"png", "jpg", "jpeg", "webp"}
ALLOWED_FILE = {"pdf", "epub", "mobi"}

def _ext_ok(filename, allowed):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed

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
    genre  = Column(String(100), nullable=True)

    cover_path = Column(String(500), nullable=True)
    file_path  = Column(String(500), nullable=True)
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

class Highlight(Base):
    __tablename__ = "highlights"
    id = Column(Integer, primary_key=True)
    note_id = Column(Integer, ForeignKey("notes.id", ondelete="CASCADE"), index=True, nullable=False)
    start = Column(Integer, nullable=False)
    end = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)

class Annotation(Base):
    __tablename__ = "annotations"
    id = Column(Integer, primary_key=True)
    note_id = Column(Integer, ForeignKey("notes.id", ondelete="CASCADE"), index=True, nullable=False)
    pos_x = Column(Integer, nullable=True)
    pos_y = Column(Integer, nullable=True)
    text = Column(Text, nullable=True)
    style = Column(String(20), nullable=True)

Base.metadata.create_all(bind=engine)

# --- HELPERS ---
EMAIL_REGEX = re.compile(
    r"^(?=.{1,254}$)(?=.{1,64}@)[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$"
)

def current_user_id():
    return session.get("uid")

def require_login():
    if not current_user_id():
        return redirect(url_for("login"))
    return None

def get_or_create_tag(db, owner_id: int, name: str) -> Tag:
    tag = db.query(Tag).filter_by(owner_id=owner_id, name=name).first()
    if tag:
        return tag
    tag = Tag(owner_id=owner_id, name=name)
    db.add(tag)
    db.flush()
    return tag

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
        if not EMAIL_REGEX.match(typed_email):
            flash("Please enter a valid email address (e.g., name@example.com).", "error")
            return render_template('login.html', email=typed_email)
        db = SessionLocal()
        user = db.query(User).filter_by(email=typed_email).first()
        ok = bool(user and check_password_hash(user.password_hash, password))
        db.close()
        if ok:
            session['uid'] = user.id
            return redirect(url_for('bookshelf'), code=302)
        flash("Invalid email or password", "error")
        return render_template('login.html', email=typed_email)
    return render_template('login.html')

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
            return render_template('register.html', email=email, email_error=email_error, password_error=password_error)
        hashed_pw = generate_password_hash(password)
        db.add(User(email=email, password_hash=hashed_pw))
        db.commit()
        db.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', email=email)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/bookshelf')
def bookshelf():
    if (redir := require_login()):
        return redir
    uid = current_user_id()
    db = SessionLocal()

    authors = [
        row[0]
        for row in db.query(Book.author)
        .filter(Book.owner_id == uid, Book.author.isnot(None), Book.author != "")
        .distinct()
        .all()
    ]
    genres = [
        row[0]
        for row in db.query(Book.genre)
        .filter(Book.owner_id == uid, Book.genre.isnot(None), Book.genre != "")
        .distinct()
        .all()
    ]
    tags = [
        t[0]
        for t in db.query(Tag.name)
        .join(book_tags, Tag.id == book_tags.c.tag_id)
        .join(Book, Book.id == book_tags.c.book_id)
        .filter(Tag.owner_id == uid, Book.owner_id == uid)
        .distinct()
        .all()
    ]

    selected_author = request.args.get('author', '').strip()
    selected_genre  = request.args.get('genre', '').strip()
    selected_tag    = request.args.get('tag', '').strip()

    q = db.query(Book).filter(Book.owner_id == uid)
    if selected_author:
        q = q.filter(Book.author == selected_author)
    if selected_genre:
        q = q.filter(Book.genre == selected_genre)
    if selected_tag:
        q = q.join(Book.tags).filter(Tag.name == selected_tag, Tag.owner_id == uid)

    books_raw = q.order_by(Book.created_at.desc()).all()
    book_count = db.query(Book).filter(Book.owner_id == uid).count()

    books = []
    for b in books_raw:
        cover_url = b.cover_path or url_for('static', filename='img/cover_placeholder.png')
        current = b.progress.current_page if b.progress else None
        total   = getattr(b, 'total_pages', None)
        tag_names = [t.name for t in b.tags] if b.tags else []
        meta_bits = []
        if b.genre:
            meta_bits.append(b.genre)
        if tag_names:
            meta_bits.extend(tag_names)
        meta_line = ", ".join(meta_bits)
        books.append({
            "id": b.id,
            "title": b.title,
            "author": b.author or "",
            "genre": b.genre or "",
            "tags": tag_names,
            "cover_url": cover_url,
            "progress_current": current,
            "progress_total": total,
            "meta_line": meta_line,
            "is_digital": bool(b.file_path),
        })

    db.close()
    return render_template(
        'bookshelf.html',
        authors=authors, genres=genres, tags=tags,
        selected_author=selected_author, selected_genre=selected_genre, selected_tag=selected_tag,
        book_count=book_count, books=books
    )

@app.route('/books/new', methods=['POST'])
def add_book():
    if (redir := require_login()):
        return redir
    uid = current_user_id()
    title = (request.form.get('title') or "").strip()
    author = (request.form.get('author') or "").strip()
    genre  = (request.form.get('genre')  or "").strip()
    tags_raw = (request.form.get('tags') or "").strip()

    if not title:
        flash("Title is required.", "error")
        return redirect(url_for('bookshelf'))

    cover_path = None
    file_path = None

    cover = request.files.get('cover')
    if cover and cover.filename and _ext_ok(cover.filename, ALLOWED_COVER):
        fname = f"{uid}_{int(datetime.utcnow().timestamp())}_cover_{secure_filename(cover.filename)}"
        cover.save(os.path.join(UPLOAD_DIR, fname))
        cover_path = f"uploads/{fname}"

    doc = request.files.get('file')
    if doc and doc.filename and _ext_ok(doc.filename, ALLOWED_FILE):
        fname = f"{uid}_{int(datetime.utcnow().timestamp())}_file_{secure_filename(doc.filename)}"
        doc.save(os.path.join(UPLOAD_DIR, fname))
        file_path = f"uploads/{fname}"

    db = SessionLocal()
    try:
        book = Book(
            owner_id=uid,
            title=title,
            author=author or None,
            genre=genre or None,
            cover_path=cover_path,
            file_path=file_path
        )
        db.add(book)
        db.flush()
        db.add(ReadingProgress(book_id=book.id, current_page=0))

        if tags_raw:
            for raw in re.split(r"[,\n]", tags_raw):
                name = raw.strip()
                if not name:
                    continue
                tag = get_or_create_tag(db, uid, name)
                book.tags.append(tag)

        db.commit()
        flash("Book added to your shelf!", "success")
    except Exception as e:
        db.rollback()
        flash("Could not save book. Please try again.", "error")
        print("Add book error:", e)
    finally:
        db.close()

    return redirect(url_for('bookshelf'))

@app.route('/books/<int:book_id>/edit', methods=['POST'])
def edit_book(book_id):
    if (redir := require_login()):
        return redir
    uid = current_user_id()
    db = SessionLocal()
    try:
        book = db.query(Book).filter(Book.id == book_id, Book.owner_id == uid).first()
        if not book:
            db.close()
            flash("Book not found.", "error")
            return redirect(url_for('bookshelf'))

        title   = (request.form.get('title')  or "").strip()
        author  = (request.form.get('author') or "").strip()
        genre   = (request.form.get('genre')  or "").strip()
        tags_raw = (request.form.get('tags')  or "").strip()

        if title:
            book.title = title
        book.author = author or None
        book.genre  = genre or None

        cover = request.files.get('cover')
        if cover and cover.filename and _ext_ok(cover.filename, ALLOWED_COVER):
            fname = f"{uid}_{int(datetime.utcnow().timestamp())}_cover_{secure_filename(cover.filename)}"
            cover.save(os.path.join(UPLOAD_DIR, fname))
            book.cover_path = f"uploads/{fname}"

        book.tags.clear()
        if tags_raw:
            for raw in re.split(r"[,\n]", tags_raw):
                name = raw.strip()
                if not name:
                    continue
                tag = get_or_create_tag(db, uid, name)
                book.tags.append(tag)

        db.commit()
        flash("Book updated.", "success")
    except Exception as e:
        db.rollback()
        flash("Could not update book.", "error")
        print("Edit book error:", e)
    finally:
        db.close()

    return redirect(url_for('bookshelf'))

@app.route('/books/<int:book_id>/delete', methods=['POST'])
def delete_book(book_id):
    if (redir := require_login()):
        return redir
    uid = current_user_id()
    db = SessionLocal()
    try:
        book = db.query(Book).filter(Book.id == book_id, Book.owner_id == uid).first()
        if not book:
            db.close()
            flash("Book not found.", "error")
            return redirect(url_for('bookshelf'))
        db.delete(book)
        db.flush()

        # cleanup: remove any of this user's tags that no longer have books
        orphan_tags = (
            db.query(Tag)
            .filter(Tag.owner_id == uid)
            .all()
        )
        for t in orphan_tags:
            if not t.books:
                db.delete(t)

        db.commit()
        flash("Book removed.", "success")
    except Exception as e:
        db.rollback()
        flash("Could not remove book.", "error")
        print("Delete book error:", e)
    finally:
        db.close()
    return redirect(url_for('bookshelf'))

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    server = Server(app.wsgi_app)
    server.serve(port=5001, debug=True)