import os
import re
import random
import string
import base64
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from translations import T
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key-12345')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///kandahar.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'shop_login'

# ---------- SUPABASE SETUP ----------
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
BUCKET_NAME = 'kandahar-photos'

supabase_client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- LANGUAGES ----------
LANGUAGES = ['en', 'ps', 'fa']
@app.before_request
def set_language():
    lang = request.args.get('lang')
    if lang in LANGUAGES:
        session['lang'] = lang
    if 'lang' not in session:
        session['lang'] = 'en'

def get_text(key):
    lang = session.get('lang', 'en')
    return T[lang].get(key, key)

@app.context_processor
def inject_translations():
    return dict(t=get_text, current_lang=session.get('lang', 'en'))

# ---------- MODELS ----------
class Shop(UserMixin, db.Model):
    __tablename__ = 'shops'
    id = db.Column(db.Integer, primary_key=True)
    shop_name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    contact = db.Column(db.String(20))
    email = db.Column(db.String(120), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='shop')
    is_blocked = db.Column(db.Boolean, default=False)
    mobiles = db.relationship('Mobile', backref='owner_shop', lazy=True, cascade="all, delete-orphan")

class Mobile(db.Model):
    __tablename__ = 'mobiles'
    id = db.Column(db.Integer, primary_key=True)
    imei1 = db.Column(db.String(15), index=True, nullable=False)
    imei2 = db.Column(db.String(15), index=True)
    color = db.Column(db.String(30))
    model = db.Column(db.String(100))
    brand = db.Column(db.String(50))
    source_type = db.Column(db.String(20), default='local')
    customer_name = db.Column(db.String(100))
    customer_phone = db.Column(db.String(20))
    tazkira_number = db.Column(db.String(50))
    tazkira_photo = db.Column(db.String(300))
    selfie_photo = db.Column(db.String(300))
    purchase_price = db.Column(db.Integer, default=0)  # ✅ Purchase Price
    status = db.Column(db.String(20), default='active')
    shop_id = db.Column(db.Integer, db.ForeignKey('shops.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    stolen_report = db.relationship('StolenReport', backref='mobile', uselist=False, cascade="all, delete-orphan")
    detection_logs = db.relationship('DetectionLog', backref='mobile', cascade="all, delete-orphan")

class StolenReport(db.Model):
    __tablename__ = 'stolen_reports'
    id = db.Column(db.Integer, primary_key=True)
    mobile_id = db.Column(db.Integer, db.ForeignKey('mobiles.id'), unique=True)
    reported_by_shop_id = db.Column(db.Integer, db.ForeignKey('shops.id'))
    description = db.Column(db.Text)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)

class DetectionLog(db.Model):
    __tablename__ = 'detection_logs'
    id = db.Column(db.Integer, primary_key=True)
    mobile_id = db.Column(db.Integer, db.ForeignKey('mobiles.id'))
    detected_at_shop_id = db.Column(db.Integer, db.ForeignKey('shops.id'))
    detected_date = db.Column(db.DateTime, default=datetime.utcnow)
    location = db.Column(db.String(200))

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('shops.id'))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class IMEICheckLog(db.Model):
    __tablename__ = 'imei_check_logs'
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(15), index=True, nullable=False)
    checked_by = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    status = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_suspicious = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(shop_id):
    return Shop.query.get(int(shop_id))

# ---------- HELPERS ----------
def is_valid_imei(imei):
    if not imei:
        return True
    return bool(re.match(r'^\d{15}$', imei))

def notify_shop(shop_id, message):
    notif = Notification(shop_id=shop_id, message=message)
    db.session.add(notif)
    db.session.commit()

def upload_to_supabase(file, folder_name):
    try:
        file.seek(0)
        file_data = file.read()
        timestamp = datetime.utcnow().timestamp()
        original_filename = file.filename
        if '.' in original_filename:
            extension = original_filename.rsplit('.', 1)[1].lower()
        else:
            extension = 'jpg'
        filename = f"{timestamp}.{extension}"
        file_path = f"{folder_name}/{filename}"

        url = f"{SUPABASE_URL}/storage/v1/object/{BUCKET_NAME}/{file_path}"
        headers = {
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": file.content_type,
            "x-upsert": "true"
        }
        response = requests.post(url, headers=headers, data=file_data)
        if response.status_code in [200, 201]:
            public_url = f"{SUPABASE_URL}/storage/v1/object/public/{BUCKET_NAME}/{file_path}"
            return public_url
        else:
            print(f"Upload failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Upload exception: {str(e)}")
        return None

def delete_photo_from_supabase(photo_url):
    """Delete a photo from Supabase Storage given its public URL."""
    if not photo_url:
        return
    try:
        # Extract the file path from the public URL
        # Example: https://.../storage/v1/object/public/kandahar-photos/tazkira/123.jpg
        parts = photo_url.split(f'/public/{BUCKET_NAME}/')
        if len(parts) == 2:
            file_path = parts[1]
            supabase_client.storage.from_(BUCKET_NAME).remove([file_path])
            print(f"Deleted photo: {file_path}")
        else:
            print(f"Invalid URL format: {photo_url}")
    except Exception as e:
        print(f"Error deleting photo: {e}")

# ---------- ROUTES ----------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('shop_dashboard'))
    return redirect(url_for('shop_login'))

@app.route('/shop/login', methods=['GET', 'POST'])
def shop_login():
    if request.method == 'POST':
        shop = Shop.query.filter_by(username=request.form['username']).first()
        if shop and shop.is_blocked:
            flash('Your account has been BLOCKED by Admin. Contact support.', 'danger')
            return redirect(url_for('shop_login'))
        if shop and check_password_hash(shop.password_hash, request.form['password']):
            login_user(shop)
            return redirect(url_for('shop_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('shop_login.html')

@app.route('/shop/logout')
@login_required
def shop_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/shop/dashboard')
@login_required
def shop_dashboard():
    my_mobiles = Mobile.query.filter_by(shop_id=current_user.id).all()
    unread_count = Notification.query.filter_by(shop_id=current_user.id, is_read=False).count()
    stolen_alert_count = Mobile.query.filter_by(status='stolen').count()
    return render_template('shop_dashboard.html', mobiles=my_mobiles, unread_count=unread_count, stolen_alert_count=stolen_alert_count)

@app.route('/shop/add-mobile', methods=['GET', 'POST'])
@login_required
def add_mobile():
    if request.method == 'POST':
        imei1 = request.form['imei1'].strip()
        imei2 = request.form['imei2'].strip() if request.form['imei2'] else None
        color = request.form['color'].strip()
        source_type = request.form['source_type']
        purchase_price = request.form.get('purchase_price', 0, type=int)

        if not is_valid_imei(imei1):
            flash(get_text('invalid_imei'), 'danger')
            return redirect(url_for('add_mobile'))
        if imei2 and not is_valid_imei(imei2):
            flash(get_text('invalid_imei'), 'danger')
            return redirect(url_for('add_mobile'))

        customer_name = request.form.get('customer_name', '').strip()
        customer_phone = request.form.get('customer_phone', '').strip()
        tazkira_number = request.form.get('tazkira_number', '').strip()

        if source_type == 'local':
            if not customer_name or not customer_phone or not tazkira_number:
                flash('For Local Purchase, Customer Name, Phone, and Tazkira ID are required!', 'danger')
                return redirect(url_for('add_mobile'))

        # ---------- UPLOAD PHOTOS ----------
        tazkira_photo_url = None
        if 'tazkira_photo' in request.files:
            file = request.files['tazkira_photo']
            if file and file.filename != '':
                tazkira_photo_url = upload_to_supabase(file, 'tazkira')
                if not tazkira_photo_url:
                    flash('Error uploading Tazkira photo. Please try again.', 'danger')
                    return redirect(url_for('add_mobile'))

        selfie_photo_url = None
        if 'selfie_photo' in request.files:
            file = request.files['selfie_photo']
            if file and file.filename != '':
                selfie_photo_url = upload_to_supabase(file, 'selfie')
                if not selfie_photo_url:
                    flash('Error uploading Selfie photo. Please try again.', 'danger')
                    return redirect(url_for('add_mobile'))

        # ---------- STOLEN CHECK ----------
        stolen_mobile = Mobile.query.filter(
            Mobile.status == 'stolen',
            (Mobile.imei1 == imei1) | (Mobile.imei2 == imei1) |
            (Mobile.imei1 == imei2) | (Mobile.imei2 == imei2)
        ).first()

        # ---------- NEW MOBILE ----------
        new_mobile = Mobile(
            imei1=imei1,
            imei2=imei2,
            color=color,
            model=request.form['model'],
            brand=request.form['brand'],
            source_type=source_type,
            customer_name=customer_name if source_type == 'local' else None,
            customer_phone=customer_phone if source_type == 'local' else None,
            tazkira_number=tazkira_number if source_type == 'local' else None,
            tazkira_photo=tazkira_photo_url if source_type == 'local' else None,
            selfie_photo=selfie_photo_url if source_type == 'local' else None,
            purchase_price=purchase_price,
            shop_id=current_user.id,
            status='active'
        )
        db.session.add(new_mobile)
        db.session.commit()

        if stolen_mobile:
            new_mobile.status = 'stolen'
            detection = DetectionLog(
                mobile_id=new_mobile.id,
                detected_at_shop_id=current_user.id,
                location=current_user.location
            )
            db.session.add(detection)

            if stolen_mobile.shop_id:
                original_owner = Shop.query.get(stolen_mobile.shop_id)
                if original_owner:
                    notify_shop(
                        original_owner.id,
                        get_text('stolen_found_alert').format(
                            brand=stolen_mobile.brand,
                            model=stolen_mobile.model,
                            imei=stolen_mobile.imei1,
                            shop=current_user.shop_name,
                            name=customer_name if customer_name else 'N/A',
                            phone=customer_phone if customer_phone else 'N/A',
                            tazkira=tazkira_number if tazkira_number else 'N/A'
                        )
                    )
            admin = Shop.query.filter_by(username='admin').first()
            if admin:
                notify_shop(
                    admin.id,
                    get_text('stolen_added_alert').format(
                        shop=current_user.shop_name,
                        imei=imei1,
                        name=customer_name if customer_name else 'N/A',
                        phone=customer_phone if customer_phone else 'N/A',
                        tazkira=tazkira_number if tazkira_number else 'N/A',
                        selfie='Uploaded' if selfie_photo_url else 'Not uploaded'
                    )
                )
            notify_shop(
                current_user.id,
                get_text('hold_seller_alert')
            )
            db.session.commit()
            flash(get_text('hold_seller_alert'), 'danger')
        else:
            flash(get_text('add_success'), 'success')
        return redirect(url_for('shop_dashboard'))
    return render_template('add_mobile.html')

@app.route('/shop/notifications')
@login_required
def notifications():
    notifs = Notification.query.filter_by(shop_id=current_user.id).order_by(Notification.created_at.desc()).all()
    for n in notifs:
        n.is_read = True
    db.session.commit()
    return render_template('notifications.html', notifications=notifs)

@app.route('/shop/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        if not check_password_hash(current_user.password_hash, old):
            flash('Old password incorrect.', 'danger')
            return redirect(url_for('change_password'))
        if new != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('change_password'))
        if len(new) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return redirect(url_for('change_password'))
        current_user.password_hash = generate_password_hash(new)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('shop_dashboard'))
    return render_template('change_password.html')

# ---------- ADMIN ROUTES ----------
@app.route('/admin/shops')
@login_required
def admin_shops():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    all_shops = Shop.query.all()
    return render_template('admin_shops.html', shops=all_shops)

# ---------- PWA MANIFEST ----------
@app.route('/manifest.json')
def manifest():
    return {
        "name": "Kandahar Mobile System",
        "short_name": "Kandahar Mobile",
        "start_url": "/",
        "display": "standalone",   # Yeh full screen ke liye zaroori hai
        "orientation": "portrait",
        "scope": "/",
        "background_color": "#1a3a5c",
        "theme_color": "#1a3a5c",
        "icons": [
            {
                "src": "/static/icon-192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "/static/icon-512.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ]
    }

@app.route('/admin/change-role/<int:shop_id>', methods=['POST'])
@login_required
def change_role(shop_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    shop = Shop.query.get_or_404(shop_id)
    new_role = request.form['role']
    if new_role in ['admin', 'shop']:
        shop.role = new_role
        db.session.commit()
        flash('Role updated.', 'success')
    else:
        flash('Invalid role.', 'danger')
    return redirect(url_for('admin_shops'))

@app.route('/admin/delete-shop/<int:shop_id>', methods=['POST'])
@login_required
def admin_delete_shop(shop_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    shop = Shop.query.get_or_404(shop_id)
    if shop.username == 'admin':
        flash('Cannot delete main admin.', 'danger')
        return redirect(url_for('admin_shops'))
    Notification.query.filter_by(shop_id=shop_id).delete()
    db.session.delete(shop)
    db.session.commit()
    flash('Shop deleted successfully!', 'success')
    return redirect(url_for('admin_shops'))

@app.route('/admin/reset-password/<int:shop_id>', methods=['POST'])
@login_required
def admin_reset_password(shop_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    shop = Shop.query.get_or_404(shop_id)
    if shop.username == 'admin':
        flash('Cannot reset main admin password.', 'danger')
        return redirect(url_for('admin_shops'))
    new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    shop.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash(get_text('password_reset_success').format(password=new_password), 'success')
    return redirect(url_for('admin_shops'))

@app.route('/admin/add-shop', methods=['GET', 'POST'])
@login_required
def admin_add_shop():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    if request.method == 'POST':
        if Shop.query.filter_by(username=request.form['username']).first():
            flash('Username already taken!', 'danger')
            return redirect(url_for('admin_add_shop'))
        if request.form['email'] and Shop.query.filter_by(email=request.form['email']).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('admin_add_shop'))
        shop = Shop(
            shop_name=request.form['shop_name'],
            location=request.form['location'],
            contact=request.form['contact'],
            email=request.form['email'],
            username=request.form['username'],
            password_hash=generate_password_hash(request.form['password']),
            role=request.form['role']
        )
        db.session.add(shop)
        db.session.commit()
        flash('Shop added successfully!', 'success')
        return redirect(url_for('admin_add_shop'))
    return render_template('admin_add_shop.html')

@app.route('/admin/all-mobiles', methods=['GET', 'POST'])
@login_required
def admin_all_mobiles():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    query = Mobile.query
    imei_filter = request.args.get('imei', '').strip()
    shop_filter = request.args.get('shop_id', '')
    brand_filter = request.args.get('brand', '').strip()
    status_filter = request.args.get('status', '')
    if imei_filter:
        query = query.filter((Mobile.imei1.like(f"%{imei_filter}%")) | (Mobile.imei2.like(f"%{imei_filter}%")))
    if shop_filter and shop_filter.isdigit():
        query = query.filter_by(shop_id=int(shop_filter))
    if brand_filter:
        query = query.filter(Mobile.brand.like(f"%{brand_filter}%"))
    if status_filter:
        query = query.filter_by(status=status_filter)
    all_mobiles = query.order_by(Mobile.created_at.desc()).all()
    shops = Shop.query.all()
    return render_template('admin_all_mobiles.html', mobiles=all_mobiles, shops=shops,
                           filters={'imei': imei_filter, 'shop_id': shop_filter, 'brand': brand_filter, 'status': status_filter})

@app.route('/admin/search-imei', methods=['GET', 'POST'])
@login_required
def admin_search_imei():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    results = None
    if request.method == 'POST':
        imei = request.form['imei'].strip()
        if not is_valid_imei(imei):
            flash(get_text('invalid_imei'), 'danger')
            return redirect(url_for('admin_search_imei'))
        results = Mobile.query.filter((Mobile.imei1 == imei) | (Mobile.imei2 == imei)).order_by(Mobile.created_at.desc()).all()
        if not results:
            flash(get_text('not_found_message'), 'info')
    return render_template('admin_search_imei.html', results=results)

@app.route('/admin/suspicious-shops')
@login_required
def admin_suspicious_shops():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    from sqlalchemy import func
    suspicious_shops = db.session.query(
        Shop,
        func.count(IMEICheckLog.id).label('search_count')
    ).outerjoin(
        IMEICheckLog,
        (IMEICheckLog.checked_by == db.func.cast(Shop.id, db.String)) &
        (IMEICheckLog.status == 'suspicious_search')
    ).group_by(Shop.id).all()
    return render_template('admin_suspicious_shops.html', shops=suspicious_shops)

@app.route('/admin/toggle-block/<int:shop_id>', methods=['POST'])
@login_required
def admin_toggle_block(shop_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    shop = Shop.query.get_or_404(shop_id)
    if shop.username == 'admin':
        flash('Cannot block main admin.', 'danger')
        return redirect(url_for('admin_suspicious_shops'))
    shop.is_blocked = not shop.is_blocked
    db.session.commit()
    flash(f'Shop {shop.shop_name} has been {"blocked" if shop.is_blocked else "unblocked"}.', 'success')
    return redirect(url_for('admin_suspicious_shops'))

@app.route('/admin/report-stolen/<int:mobile_id>', methods=['POST'])
@login_required
def admin_report_stolen(mobile_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    mobile = Mobile.query.get_or_404(mobile_id)
    if mobile.status == 'stolen':
        flash('Already stolen.', 'warning')
        return redirect(url_for('admin_all_mobiles'))
    mobile.status = 'stolen'
    report = StolenReport(
        mobile_id=mobile.id,
        reported_by_shop_id=current_user.id,
        description=request.form.get('description', 'Admin reported')
    )
    db.session.add(report)
    if mobile.shop_id:
        notify_shop(mobile.shop_id, f"⚠️ Admin marked your {mobile.brand} {mobile.model} as STOLEN.")
    db.session.commit()
    flash('Mobile marked as STOLEN by Admin!', 'success')
    return redirect(url_for('admin_all_mobiles'))

@app.route('/admin/recover-mobile/<int:mobile_id>', methods=['POST'])
@login_required
def admin_recover_mobile(mobile_id):
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('shop_dashboard'))
    mobile = Mobile.query.get_or_404(mobile_id)
    if mobile.status not in ['stolen', 'detected']:
        flash('Not stolen.', 'warning')
        return redirect(url_for('admin_all_mobiles'))
    mobile.status = 'recovered'
    db.session.commit()
    if mobile.shop_id:
        notify_shop(mobile.shop_id, f"✅ {mobile.brand} {mobile.model} RECOVERED by Admin.")
    flash('Mobile recovered!', 'success')
    return redirect(url_for('admin_all_mobiles'))

@app.route('/shop/recover-mobile/<int:mobile_id>', methods=['POST'])
@login_required
def recover_mobile(mobile_id):
    if current_user.role != 'admin':
        flash('Access denied. Only Admin can recover mobiles.', 'danger')
        return redirect(url_for('shop_dashboard'))
    mobile = Mobile.query.get_or_404(mobile_id)
    if mobile.status not in ['stolen', 'detected']:
        flash('This mobile is not marked as stolen.', 'warning')
        return redirect(url_for('shop_dashboard'))
    mobile.status = 'recovered'
    db.session.commit()
    if mobile.shop_id:
        notify_shop(mobile.shop_id, get_text('recovered_notification').format(brand=mobile.brand, model=mobile.model, imei=mobile.imei1))
    flash('Mobile marked as recovered by Admin!', 'success')
    return redirect(url_for('admin_all_mobiles'))

# ---------- ADMIN DELETE MOBILE (with photo delete) ----------
@app.route('/admin/delete-mobile/<int:mobile_id>', methods=['POST'])
@login_required
def admin_delete_mobile(mobile_id):
    if current_user.role != 'admin':
        flash(get_text('access_denied'), 'danger')
        return redirect(url_for('shop_dashboard'))

    mobile = Mobile.query.get_or_404(mobile_id)

    # ---------- DELETE PHOTOS FROM SUPABASE ----------
    if mobile.tazkira_photo:
        delete_photo_from_supabase(mobile.tazkira_photo)
    if mobile.selfie_photo:
        delete_photo_from_supabase(mobile.selfie_photo)

    # ---------- DELETE RECORD ----------
    StolenReport.query.filter_by(mobile_id=mobile.id).delete()
    DetectionLog.query.filter_by(mobile_id=mobile.id).delete()
    db.session.delete(mobile)
    db.session.commit()

    flash(get_text('record_deleted'), 'success')
    return redirect(url_for('admin_all_mobiles'))



# ---------- API UNREAD COUNT ----------
@app.route('/api/unread-count')
@login_required
def api_unread_count():
    count = Notification.query.filter_by(shop_id=current_user.id, is_read=False).count()
    return {"count": count}

# ---------- CREATE TABLES & SEED ----------
with app.app_context():
    db.create_all()
    admin = Shop.query.filter_by(username='admin').first()
    if not admin:
        admin = Shop(
            shop_name='System Administrator',
            location='Kandahar',
            contact='0700000000',
            email='admin@kandaharsystem.com',
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created: username=admin, password=admin123")
    if Shop.query.count() == 1:
        demo = Shop(
            shop_name="Kandahar Central Mobile",
            location="Main Bazaar, Kandahar",
            contact="0700123456",
            email="demo@kandaharsystem.com",
            username="demo_shop",
            password_hash=generate_password_hash("demo123"),
            role='shop'
        )
        db.session.add(demo)
        db.session.commit()
        print("✅ Demo shop created: demo_shop / demo123")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)