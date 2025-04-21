import sqlite3
import uuid
import re
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from flask_bcrypt import Bcrypt
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!changeit'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# --- DB 연결 및 보조 함수 ---
def get_db():
    db = getattr(g, 'database', None)
    if db is None:
        db = g.database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                login_fail INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price REAL NOT NULL,
                sellerid TEXT NOT NULL,
                status TEXT DEFAULT 'active'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporterid TEXT NOT NULL,
                targetid TEXT NOT NULL,
                reason TEXT NOT NULL,
                targettype TEXT NOT NULL,
                ts INTEGER NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                senderid TEXT NOT NULL,
                receiverid TEXT,
                content TEXT NOT NULL,
                room TEXT,
                is_global INTEGER DEFAULT 0,
                ts INTEGER NOT NULL
            )
        ''')
        db.commit()

# --- 보안 헤더 ---
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# --- WTForms 폼 정의 ---
class RegisterForm(FlaskForm):
    username = StringField('아이디', validators=[
        DataRequired(), Length(min=4, max=16),
        Regexp(r'^[A-Za-z0-9_]+$', message="영문, 숫자, 언더스코어만 허용")
    ])
    password = PasswordField('비밀번호', validators=[
        DataRequired(), Length(min=8, max=32)
    ])
    submit = SubmitField('회원가입')

class LoginForm(FlaskForm):
    username = StringField('아이디', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])
    submit = SubmitField('로그인')

class ProductForm(FlaskForm):
    title = StringField('상품명', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('설명', validators=[DataRequired(), Length(max=500)])
    price = StringField('가격', validators=[
        DataRequired(), Regexp(r'^\d+(\.\d{1,2})?$', message="숫자만 입력")
    ])
    submit = SubmitField('등록')

class ProfileForm(FlaskForm):
    bio = TextAreaField('소개글', validators=[Length(max=200)])
    newpw = PasswordField('새 비밀번호', validators=[Length(min=0, max=32)])
    submit = SubmitField('수정')

class ReportForm(FlaskForm):
    targetid = StringField('신고 대상 ID', validators=[DataRequired(), Length(max=64)])
    targettype = StringField('신고유형', validators=[DataRequired(), Regexp(r'^(user|product)$')])
    reason = TextAreaField('신고사유', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('신고')

# --- 유틸리티 ---
def is_admin():
    return session.get('is_admin', False)

def rate_limit_check(user_id, action, window=10, limit=5):
    # 간단한 메모리 기반 rate limit (과제용)
    if not hasattr(app, 'rate_limit'):
        app.rate_limit = {}
    now = int(time.time())
    key = f'{user_id}:{action}'
    history = app.rate_limit.get(key, [])
    history = [t for t in history if now - t < window]
    if len(history) >= limit:
        return False
    history.append(now)
    app.rate_limit[key] = history
    return True

# --- 회원가입 ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('이미 존재하는 아이디입니다.')
            return redirect(url_for('register'))
        userid = str(uuid.uuid4())
        hashed = bcrypt.generate_password_hash(password).decode()
        cursor.execute('INSERT INTO user (id, username, password) VALUES (?, ?, ?)', (userid, username, hashed))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# --- 로그인 (로그인 실패 횟수 제한) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            if user['login_fail'] >= 5:
                flash('로그인 5회 실패로 계정이 잠겼습니다.')
                return redirect(url_for('login'))
            if bcrypt.check_password_hash(user['password'], password):
                session['userid'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                session.permanent = True
                cursor.execute('UPDATE user SET login_fail=0 WHERE id=?', (user['id'],))
                db.commit()
                flash('로그인 성공!')
                return redirect(url_for('dashboard'))
            else:
                cursor.execute('UPDATE user SET login_fail=login_fail+1 WHERE id=?', (user['id'],))
                db.commit()
                flash('비밀번호가 올바르지 않습니다.')
        else:
            flash('존재하지 않는 아이디입니다.')
    return render_template('login.html', form=form)

# --- 로그아웃 ---
@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃 되었습니다.')
    return redirect(url_for('index'))

# --- 메인/상품목록 ---
@app.route('/')
def index():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE status="active"')
    products = cursor.fetchall()
    return render_template('index.html', products=products)

# --- 대시보드(내 상품/전체 채팅) ---
@app.route('/dashboard')
def dashboard():
    if 'userid' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?', (session['userid'],))
    currentuser = cursor.fetchone()
    cursor.execute('SELECT * FROM product WHERE sellerid = ?', (session['userid'],))
    myproducts = cursor.fetchall()
    cursor.execute('SELECT * FROM product WHERE status="active"')
    allproducts = cursor.fetchall()
    return render_template('dashboard.html', products=allproducts, myproducts=myproducts, user=currentuser)

# --- 마이페이지(프로필/비번수정) ---
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'userid' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?', (session['userid'],))
    currentuser = cursor.fetchone()
    form = ProfileForm(bio=currentuser['bio'])
    if form.validate_on_submit():
        bio = escape(form.bio.data)
        newpw = form.newpw.data
        if newpw:
            hashed = bcrypt.generate_password_hash(newpw).decode()
            cursor.execute('UPDATE user SET bio=?, password=? WHERE id=?', (bio, hashed, session['userid']))
        else:
            cursor.execute('UPDATE user SET bio=? WHERE id=?', (bio, session['userid']))
        db.commit()
        flash('프로필이 수정되었습니다.')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=currentuser, form=form)

# --- 상품 등록 ---
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'userid' not in session:
        return redirect(url_for('login'))
    form = ProductForm()
    if form.validate_on_submit():
        title = escape(form.title.data)
        description = escape(form.description.data)
        try:
            price = float(form.price.data)
            if price < 0 or price > 100000000:
                raise ValueError
        except ValueError:
            flash('가격은 0~1억 사이의 숫자만 입력 가능합니다.')
            return render_template('new_product.html', form=form)
        db = get_db()
        cursor = db.cursor()
        productid = str(uuid.uuid4())
        cursor.execute('INSERT INTO product (id, title, description, price, sellerid) VALUES (?, ?, ?, ?, ?)', 
                       (productid, title, description, price, session['userid']))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html', form=form)

# --- 상품 상세 ---
@app.route('/product/<productid>')
def view_product(productid):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE id = ?', (productid,))
    product = cursor.fetchone()
    if not product:
        flash('존재하지 않는 상품입니다.')
        return redirect(url_for('dashboard'))
    cursor.execute('SELECT * FROM user WHERE id = ?', (product['sellerid'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# --- 상품 검색 ---
@app.route('/search')
def search():
    q = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM product WHERE title LIKE ? AND status="active"', (f'%{q}%',))
    products = cursor.fetchall()
    return render_template('index.html', products=products, search=q)

# --- 신고 ---
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'userid' not in session:
        return redirect(url_for('login'))
    form = ReportForm()
    if form.validate_on_submit():
        targetid = escape(form.targetid.data)
        reason = escape(form.reason.data)
        targettype = form.targettype.data
        db = get_db()
        cursor = db.cursor()
        # 신고 남용 방지: 동일 유저가 동일 대상 1시간 내 1회만
        now = int(time.time())
        cursor.execute('SELECT ts FROM report WHERE reporterid=? AND targetid=? AND targettype=? ORDER BY ts DESC LIMIT 1',
                       (session['userid'], targetid, targettype))
        last = cursor.fetchone()
        if last and now - last['ts'] < 3600:
            flash('동일 대상은 1시간에 한 번만 신고할 수 있습니다.')
            return redirect(url_for('dashboard'))
        reportid = str(uuid.uuid4())
        cursor.execute('INSERT INTO report (id, reporterid, targetid, reason, targettype, ts) VALUES (?, ?, ?, ?, ?, ?)', 
                       (reportid, session['userid'], targetid, reason, targettype, now))
        db.commit()
        # 신고 누적 차단
        if targettype == 'product':
            cursor.execute('SELECT COUNT(*) FROM report WHERE targetid=? AND targettype="product"', (targetid,))
            cnt = cursor.fetchone()[0]
            if cnt >= 5:
                cursor.execute('UPDATE product SET status="blocked" WHERE id=?', (targetid,))
                db.commit()
        elif targettype == 'user':
            cursor.execute('SELECT COUNT(*) FROM report WHERE targetid=? AND targettype="user"', (targetid,))
            cnt = cursor.fetchone()[0]
            if cnt >= 5:
                cursor.execute('UPDATE user SET status="suspended" WHERE id=?', (targetid,))
                db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html', form=form)

# --- 관리자 페이지 (유저/상품/신고 관리) ---
@app.route('/admin')
def admin():
    if not is_admin():
        abort(403)
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user')
    users = cursor.fetchall()
    cursor.execute('SELECT * FROM product')
    products = cursor.fetchall()
    cursor.execute('SELECT * FROM report')
    reports = cursor.fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)

# --- 전체 채팅 (Rate Limiting, XSS 방지, 인증 확인) ---
@socketio.on('global_message')
def handle_global_message(data):
    if 'userid' not in session:
        emit('error', {'msg': '로그인 필요'})
        return
    user_id = session['userid']
    if not rate_limit_check(user_id, 'chat', window=10, limit=5):
        emit('error', {'msg': '메시지 전송이 너무 빠릅니다.'})
        return
    content = escape(data.get('content', ''))[:200]
    msgid = str(uuid.uuid4())
    now = int(time.time())
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO message (id, senderid, content, room, is_global, ts) VALUES (?, ?, ?, ?, ?, ?)',
                   (msgid, user_id, content, 'global', 1, now))
    db.commit()
    emit('global_message', {
        'username': session.get('username', '익명'),
        'content': content
    }, broadcast=True)

# --- 1:1 채팅 (room 기반, 인증 확인, XSS, Rate Limiting) ---
@socketio.on('private_message')
def handle_private_message(data):
    if 'userid' not in session:
        emit('error', {'msg': '로그인 필요'})
        return
    user_id = session['userid']
    if not rate_limit_check(user_id, 'pm', window=10, limit=5):
        emit('error', {'msg': '메시지 전송이 너무 빠릅니다.'})
        return
    content = escape(data.get('content', ''))[:200]
    room = data.get('room')
    msgid = str(uuid.uuid4())
    now = int(time.time())
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO message (id, senderid, receiverid, content, room, is_global, ts) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (msgid, user_id, data.get('receiverid'), content, room, 0, now))
    db.commit()
    emit('private_message', {
        'username': session.get('username', '익명'),
        'content': content,
        'room': room
    }, room=room)

@socketio.on('join')
def on_join(data):
    join_room(data['room'])

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)
