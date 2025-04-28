from flask_login import login_user
from flask_login import current_user
from flask_login import LoginManager
from functools import wraps 
from flask_login import login_required
from sqlalchemy.exc import IntegrityError
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory, send_file
import os
from config import Config
from models import db, User, Farm, Animal, TransferHistory
from utils import allowed_file, create_upload_folders, generate_animal_pdf
from flask_migrate import Migrate
from flask import jsonify
from flask import Flask, jsonify, url_for, session, abort
from models import db, Farm, Animal
from sqlalchemy.exc import SQLAlchemyError
import logging
from sqlalchemy import select
from datetime import datetime, UTC , timezone
from urllib.parse import urljoin
from models import AuditLog
from werkzeug.utils import secure_filename
from flask import flash
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, FileField, SubmitField
from wtforms.validators import DataRequired
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_login import login_required, current_user
from models import db
from forms import AnimalRegistrationForm
from forms import UserForm
from forms import FarmEditForm, AnimalRegistrationForm, UserForm
from flask import make_response
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.units import inch
from io import BytesIO
from flask import send_file
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle)
from reportlab.lib.units import inch
from utils import generate_transfer_certificate
from flask import Flask





# Initialize Flask app first
app = Flask(__name__)
app.config.from_object(Config)

@app.template_filter('calculate_age')
def calculate_age(dob):
    if not dob:
        return "Unknown"
    
    today = datetime.now(timezone.utc).date()
    age_days = (today - dob).days
    
    if age_days < 30:
        return f"{age_days} days"
    elif age_days < 365:
        months = age_days // 30
        return f"{months} month{'s' if months > 1 else ''}"
    else:
        years = age_days // 365
        remaining_months = (age_days % 365) // 30
        if remaining_months > 0:
            return f"{years} year{'s' if years > 1 else ''}, {remaining_months} month{'s' if remaining_months > 1 else ''}"
        return f"{years} year{'s' if years > 1 else ''}"

# Now configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Initialize database and extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# In your app.py where you initialize the admin user
with app.app_context():
    create_upload_folders(app)
    try:
        db.create_all()
        
        # Create admin if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                full_name='Administrator',
                contact_info='admin@example.com',
                is_admin=True
            )
            try:
                admin.set_password('Admin123')  # Using valid password
                db.session.add(admin)
                db.session.commit()
                print("✓ Admin user created successfully")
            except ValueError as e:
                print(f"Error creating admin user: {str(e)}")
                print("Please use a password with:")
                print("- At least 8 characters")
                print("- At least one uppercase letter")
                print("- At least one number")
            except Exception as e:
                print(f"Database error creating admin: {str(e)}")
    
    except Exception as e:
        print(f"Database initialization error: {str(e)}")
        raise

# User loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        if not current_user.is_admin:
            flash('Administrator privileges required', 'danger')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/edit_animal/<int:animal_id>', methods=['GET', 'POST'])
@login_required
def edit_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farm = Farm.query.get_or_404(animal.farm_id)
    
    # Verify ownership
    if farm.owner_id != current_user.id:
        flash("You can only edit animals from your own farm", "danger")
        return redirect(url_for('user_dashboard'))
    
    form = AnimalRegistrationForm(obj=animal)
    
    if form.validate_on_submit():
        try:
            animal.name = form.name.data
            animal.animal_type = form.animal_type.data
            animal.gender = form.gender.data
            animal.dob = form.dob.data
            animal.dress_color = form.dress_color.data
            animal.father_lineage = form.father_lineage.data
            animal.mother_lineage = form.mother_lineage.data
            
            # Handle photo updates if needed
            if form.photo1.data:
                # Add your photo handling logic here
                pass
                
            if form.photo2.data:
                # Add your photo handling logic here
                pass
                
            db.session.commit()
            flash('Animal updated successfully', 'success')
            return redirect(url_for('user_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating animal: {str(e)}', 'error')
    
    return render_template('edit_animal.html', 
                         animal=animal,
                         form=form)

# File serving routes
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    try:
        # Basic security check
        if '..' in filename or filename.startswith('/'):
            abort(404)

        # Compose full path
        upload_dir = current_app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_dir, filename)

        # Verify file exists
        if not os.path.isfile(file_path):
            current_app.logger.warning(f"File not found: {file_path}")
            abort(404)

        # Serve from the correct directory
        directory = os.path.dirname(file_path)
        file = os.path.basename(file_path)
        return send_from_directory(directory, file)

    except Exception as e:
        current_app.logger.error(f"Error serving file: {str(e)}")
        abort(404)

@app.route('/logo/<path:filename>')
def serve_logo(filename):
    """Serve logo files from the uploads/logos directory"""
    try:
        # Normalize path - replace backslashes and remove duplicate 'logos/'
        filename = filename.replace('\\', '/').replace('logos/', '')
        
        # Security check
        if '..' in filename or filename.startswith('/'):
            abort(404)
        
        # Get the correct path
        logo_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'logos')
        full_path = os.path.join(logo_dir, filename)
        
        # Verify the file exists
        if not os.path.exists(full_path):
            current_app.logger.error(f"Logo file not found: {full_path}")
            abort(404)
            
        return send_from_directory(logo_dir, filename)
    except Exception as e:
        current_app.logger.error(f"Error serving logo: {str(e)}")
        abort(404)

@app.route('/request_transfer/<int:animal_id>', methods=['POST'])
@login_required
def request_transfer(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    current_farm = animal.farm
    
    transfer = TransferHistory(
        animal_id=animal.id,
        from_farm_id=current_farm.id,
        to_farm_id=request.form['to_farm_id'],
        transferred_by=current_user.id,
        status='pending',
        notes=request.form.get('notes', '')
    )
    
    animal.transfer_request = transfer.to_farm_id
    animal.status = 'transfer_pending'
    
    db.session.add(transfer)
    db.session.commit()

@app.route('/debug/create_test_transfer/<int:animal_id>')
@admin_required
def create_test_transfer(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farms = Farm.query.filter(Farm.id != animal.farm_id).limit(1).all()
    
    if not farms:
        flash("No other farms available for transfer", "danger")
        return redirect(url_for('admin_dashboard'))
    
    transfer = TransferHistory(
        animal_id=animal.id,
        from_farm_id=animal.farm_id,
        to_farm_id=farms[0].id,
        transferred_by=current_user.id,
        status='pending',
        notes='Test transfer created by admin',
        transfer_date=datetime.now(timezone.utc)
    )
    
    db.session.add(transfer)
    db.session.commit()
    
    flash(f"Test transfer created for {animal.name}", "success")
    return redirect(url_for('view_transfer_requests'))

# Main application routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('index.html')

@app.route('/')
def hello_world():
    return 'Hello, World!'
    
    # For authenticated users
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # For regular users
    farm = Farm.query.filter_by(owner_id=current_user.id).first()
    if farm:
        if farm.status == 'approved':
            return redirect(url_for('user_dashboard'))
        else:
            flash('Your farm registration is pending approval', 'info')
    else:
        flash('Please register your farm first', 'warning')
    
    return render_template('index.html')

# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Get form data
            farm_name = request.form.get('farm_name', '').strip()
            owner_name = request.form.get('owner_name', '').strip()
            location = request.form.get('location', '').strip()
            contact = request.form.get('contact', '').strip()
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            # Validate required fields
            if not all([farm_name, owner_name, location, contact, username, password]):
                flash('All fields are required', 'error')
                return redirect(url_for('register'))

            # Password validation
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'error')
                return redirect(url_for('register'))
            if not any(char.isdigit() for char in password):
                flash('Password must contain at least one number', 'error')
                return redirect(url_for('register'))
            if not any(char.isupper() for char in password):
                flash('Password must contain at least one uppercase letter', 'error')
                return redirect(url_for('register'))

            # Check for existing username
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return redirect(url_for('register'))

            # Check for existing farm name
            if Farm.query.filter_by(farm_name=farm_name).first():
                flash('Farm name already exists', 'error')
                return redirect(url_for('register'))

            # Initialize logo_path as None by default
            logo_path = None
            
            # Handle file upload only if a file was provided
            logo = request.files.get('logo')
            if logo and logo.filename:
                if not allowed_file(logo.filename):
                    flash('Invalid file type. Allowed: JPG, PNG, GIF', 'error')
                    return redirect(url_for('register'))

                # Create secure filename
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                file_ext = os.path.splitext(logo.filename)[1].lower()
                filename = f"{secure_filename(farm_name)}_{timestamp}{file_ext}"
                logo_path = os.path.join('logos', filename)
                
                # Ensure upload directory exists
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'logos'), exist_ok=True)
                
                # Save file
                logo.save(os.path.join(app.config['UPLOAD_FOLDER'], logo_path))
                
                # Verify file was saved
                if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], logo_path)):
                    flash('Failed to save logo file', 'error')
                    return redirect(url_for('register'))

            # Create and save user first
            new_user = User(
                username=username,
                full_name=owner_name,
                contact_info=contact,
                is_admin=False
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.flush()  # This generates the ID but doesn't commit
            
            # Create farm with owner_id
            new_farm = Farm(
                owner_id=new_user.id,
                farm_name=farm_name,
                location=location,
                contact_info=contact,
                logo_path=logo_path,
                status='pending'
            )
            db.session.add(new_farm)
            
            # Commit both objects together
            db.session.commit()
            
            flash('Farm Registration successful, Awaiting for admin approval!', 'success')
            return redirect(url_for('login'))
            
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Database error: {str(e)}')
            flash('Registration failed due to database error', 'error')
            return redirect(url_for('register'))
        except ValueError as e:
            db.session.rollback()
            flash(str(e), 'error')
            return redirect(url_for('register'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error: {str(e)}')
            flash('Registration failed', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/admin/audit_logs')
@admin_required
def admin_audit_logs():
    try:
        page = request.args.get('page', 1, type=int)
        logs = AuditLog.query.options(
            db.joinedload(AuditLog.user)
        ).order_by(AuditLog.timestamp.desc()).paginate(
            page=page, 
            per_page=20,
            error_out=False
        )
        
        # Handle case where logs might be empty
        if not logs.items:
            flash('No audit logs found', 'info')
        
        return render_template('admin/audit_logs.html', 
                            logs=logs,
                            current_time=datetime.now(timezone.utc))
        
    except Exception as e:
        current_app.logger.error(f"Error accessing audit logs: {str(e)}", exc_info=True)
        flash('Error loading audit logs', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/api/audit_logs')
def api_audit_logs():
    if not session.get('is_admin'):
        abort(403)
        
    logs = AuditLog.query.limit(100).all()
    return jsonify([{
        'timestamp': log.timestamp.isoformat(),
        'user': log.user.username,
        'action': log.action_type,
        'entity': log.table_name,
        'record_id': log.record_id,
        'details': log.details
    } for log in logs])


@app.route('/admin/get_animals/<int:farm_id>')
def admin_get_animals(farm_id):
    """
    Get all animals for a specific farm (admin only)
    Returns JSON with:
    - Farm details
    - Animal list with photos
    - Metadata including count and timestamp
    """
    # Authentication check
    if not session.get('is_admin'):
        app.logger.warning(f"Unauthorized access attempt to farm {farm_id}")
        abort(403, description="Administrator privileges required")

    try:
        # Get farm with proper error handling
        farm = db.session.get(Farm, farm_id)
        if not farm:
            app.logger.info(f"Requested farm {farm_id} not found")
            return jsonify({
                'success': False,
                'error': 'Farm not found',
                'code': 'FARM_NOT_FOUND'
            }), 404

        # Efficient animal query with only needed fields
        animals = db.session.execute(
            select(
                Animal.animal_id,
                Animal.name,
                Animal.animal_type,
                Animal.gender,
                Animal.status,
                Animal.dob,
                Animal.photo1_path,
                Animal.photo2_path
            ).where(Animal.farm_id == farm_id)
        ).mappings().all()  # Returns dictionaries for cleaner access

        # Build response data
base_url = request.url_root
animals_data = []

for animal in animals:
    try:
        # Construct animal data
        animal_data = {
            'id': animal['animal_id'],
            'name': animal['name'],
            'type': animal['animal_type'].title(),
            'gender': animal['gender'].title(),
            'status': animal['status'],
            'dob': animal['dob'].isoformat() if animal['dob'] else None,
            'details_url': urljoin(base_url, f'/view_animal/{animal["animal_id"]}'),
            'photos': [
                urljoin(base_url, '/uploads/' + photo_path.replace("\\", "/"))
                for photo_path in [animal['photo1_path'], animal['photo2_path']]
                if photo_path
            ]
        }
        animals_data.append(animal_data)
    except Exception as e:
        app.logger.error(f"Error processing animal {animal.get('animal_id')}: {str(e)}")
        continue

        # Prepare response
        response_data = {
            'success': True,
            'farm': {
                'id': farm.farm_id,
                'name': farm.farm_name,
                'logo': urljoin(base_url, f'/uploads/{farm.logo_path.replace("\\", "/")}') if farm.logo_path else None,
                'location': farm.location,
                'contact': farm.contact_info
            },
            'animals': animals_data,
            'meta': {
                'count': len(animals_data),
                'timestamp': datetime.now(UTC).isoformat(),
                'api_version': '1.2'
            }
        }

        return jsonify(response_data)

    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error for farm {farm_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Database operation failed',
            'code': 'DB_ERROR'
        }), 500

    except Exception as e:
        app.logger.error(f"Unexpected error for farm {farm_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'code': 'SERVER_ERROR'
        }), 500
    
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_manage_users():
    try:
        users = User.query.order_by(User.username).all()
        return render_template('admin/user_management.html', 
                            users=users,
                            current_time=datetime.now(timezone.utc))
    
    except Exception as e:
        current_app.logger.error(f"Error accessing user management: {str(e)}")
        flash('Error loading user management', 'danger')
        return redirect(url_for('admin_dashboard'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            # Update last login if column exists
            if hasattr(user, 'last_login'):
                user.last_login = datetime.now(timezone.utc)
                db.session.commit()
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            elif user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Admin routes
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get pending farms with owner information
    pending_farms = Farm.query.filter_by(status='pending').options(
        db.joinedload(Farm.owner)
    ).all()
    
    # Get pending animals with farm and owner information
    pending_animals = Animal.query.filter_by(status='pending').options(
        db.joinedload(Animal.farm).joinedload(Farm.owner)
    ).all()
    
    # Get approved farms
    approved_farms = Farm.query.filter_by(status='approved').options(
        db.joinedload(Farm.owner)
    ).all()
    
    # Get all users
    all_users = User.query.order_by(User.username).all()
    
    # Get stats
    farm_stats = {
        'total': Farm.query.count(),
        'pending': Farm.query.filter_by(status='pending').count(),
        'approved': Farm.query.filter_by(status='approved').count()
    }
    
    animal_stats = {
        'pending': Animal.query.filter_by(status='pending').count()
    }
    
    user_stats = {
        'active': User.query.count()
    }
    
    recent_activities = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).limit(10).all()
    
    return render_template('admin_dashboard.html',
                         pending_farms=pending_farms,
                         pending_animals=pending_animals,
                         approved_farms=approved_farms,
                         all_users=all_users,  # Pass users to template
                         farm_stats=farm_stats,
                         animal_stats=animal_stats,
                         user_stats=user_stats,
                         recent_activities=recent_activities)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ''
    return value.strftime(format)

@app.template_filter('dateformat')
def dateformat(value, format='%Y-%m-%d'):
    if value is None:
        return ''
    return value.strftime(format)

@app.route('/admin/deactivate_farm/<int:farm_id>', methods=['POST'])
@admin_required
def deactivate_farm(farm_id):
    farm = Farm.query.get_or_404(farm_id)
    farm.status = 'inactive'
    
    # Create audit log with correct field names
    log = AuditLog(
        user_id=current_user.id,
        action=f"Deactivated farm {farm.farm_name}",
        table_name="farms",      # Changed from entity_type
        record_id=farm.id,       # Changed from record_id
        details=request.form.get('deactivate_reason', 'No reason provided')
    )
    
    db.session.add(log)
    db.session.commit()
    
    flash('Farm deactivated successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('admin_reset_password', user_id=user.id))
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('admin_reset_password', user_id=user.id))
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        # Log the action
        log = AuditLog(
            user_id=current_user.id,
            action=f"Reset password for user {user.username}",
            table_name='user',
            record_id=user.id
        )
        db.session.add(log)
        db.session.commit()
        
        flash('Password has been reset successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/reset_password.html', user=user)

@app.route('/admin/users')
@admin_required
def user_management():
    try:
        if not current_user.is_admin:
            flash('Administrator access required', 'danger')
            return redirect(url_for('admin_dashboard'))

        users = User.query.order_by(User.username).all()
        return render_template('admin/user_management.html', 
                            users=users,
                            current_time=datetime.now(timezone.utc))
    
    except Exception as e:
        current_app.logger.error(f"Error accessing user management: {str(e)}")
        flash('Error loading user management', 'danger')
        return redirect(url_for('admin_dashboard'))
    
@app.route('/check_admin')
@login_required
def check_admin():
    return jsonify({
        'is_admin': current_user.is_admin,
        'username': current_user.username
    })

@app.route('/make_me_admin')
def make_me_admin():
    user = User.query.filter_by(username='your_username').first()
    if user:
        user.is_admin = True
        db.session.commit()
        return "You are now an admin"
    return "User not found"

@app.route('/admin/create_user', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    form = UserForm()
    
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                full_name=form.full_name.data,
                contact_info=form.contact_info.data,
                is_admin=form.is_admin.data
            )
            user.set_password(form.password.data)
            
            # Handle farm relationship
            if form.farm_id.data and form.farm_id.data != 0:
                farm = Farm.query.get(form.farm_id.data)
                if farm:
                    if form.farm_relation.data == 'owner':
                        farm.owner = user
                    elif form.farm_relation.data == 'worker':
                        farm.workers.append(user)
            
            db.session.add(user)
            db.session.commit()
            
            flash('User created successfully', 'success')
            return redirect(url_for('user_management'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')
    
    return render_template('admin/create_user.html', form=form)

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        # Handle form submission
        pass
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting admin or current user
    if user.is_admin or user.id == current_user.id:
        flash('Cannot delete this user', 'danger')
        return redirect(url_for('user_management'))
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('user_management'))


@app.route('/admin/farm_details/<int:farm_id>')
@login_required
@admin_required
def admin_farm_details(farm_id):
    # Get farm with owner and animals
    farm = Farm.query.options(
        db.joinedload(Farm.owner),
        db.joinedload(Farm.animals)
    ).get_or_404(farm_id)
    
    return render_template('admin_farm_details.html',
                         farm=farm)

# Farm Approval Routes
@app.route('/admin/approve_farm/<int:farm_id>')
@admin_required
def approve_farm(farm_id):
    farm = Farm.query.get_or_404(farm_id)
    farm.status = 'approved'
    
    # Create audit log with correct field names
    log = AuditLog(
        user_id=current_user.id,          # Not admin_id
        action=f'Approved farm {farm.farm_name}',
        table_name='farms',              # Not table_name
        record_id=farm.id                # Not record_id
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f'Farm "{farm.farm_name}" approved', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_farm/<int:farm_id>')
@login_required
@admin_required
def reject_farm(farm_id):
    farm = Farm.query.get_or_404(farm_id)
    farm.status = 'rejected'
    
    # Log the rejection
    log = AuditLog(
        user_id=current_user.id,
        action=f'Rejected farm {farm.farm_name}',
        table_name='farm',
        record_id=farm.id
    )
    db.session.add(log)
    db.session.commit()
    
    flash(f'Farm "{farm.farm_name}" rejected', 'warning')
    return redirect(url_for('admin_dashboard'))

# Animal Approval Routes
@app.route('/admin/approve_animal/<int:animal_id>')
@login_required
@admin_required
def approve_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    animal.status = 'approved'
    
    # Log the approval
    log = AuditLog(
        user_id=current_user.id,
        action=f'Approved animal {animal.name} (ID: {animal.id})',
        table_name='animal',
        record_id=animal.id
    )
    
    db.session.add(log)
    db.session.commit()
    
    flash(f'Animal "{animal.name}" approved successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject_animal/<int:animal_id>')
@login_required
@admin_required
def reject_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    animal.status = 'rejected'
    
    # Log the rejection
    log = AuditLog(
        user_id=current_user.id,
        action=f'Rejected animal {animal.name} (ID: {animal.id})',
        table_name='animal',
        record_id=animal.id
    )
    
    db.session.add(log)
    db.session.commit()
    
    flash(f'Animal "{animal.name}" has been rejected', 'warning')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reject_animal/<int:animal_id>')
def admin_reject_animal(animal_id):
    if not session.get('is_admin'):
        abort(403)
    
    animal = Animal.query.get_or_404(animal_id)
    animal.status = 'rejected'
    db.session.commit()
    flash('Animal rejected', 'info')
    return redirect(url_for('admin_farm_details', farm_id=animal.farm_id))

@app.route('/admin/approve_transfer/<int:animal_id>')
@login_required
@admin_required
def admin_approve_transfer(animal_id):
    try:
        animal = Animal.query.get_or_404(animal_id)
        
        # Get ALL pending transfer requests for this animal (not just latest)
        pending_transfers = TransferHistory.query.filter_by(
            animal_id=animal_id,
            status='pending'
        ).all()

        if not pending_transfers:
            flash(f'No pending transfer requests found for animal {animal.name} (ID: {animal_id})', 'warning')
            return redirect(url_for('view_transfer_requests'))

        # Process all pending transfers (though typically there should be only one)
        for transfer in pending_transfers:
            # Assign the destination farm
            target_farm = transfer.to_farm
            
            # Update the transfer record
            transfer.status = 'approved'
            transfer.approved_by = current_user.id
            transfer.approval_date = datetime.now(timezone.utc)
            
            # Update the animal record
            animal.farm_id = target_farm.id
            animal.status = 'approved'
            
            # Log the action
            current_user.log_action(
                action=f"Approved transfer of animal {animal.name} to {target_farm.farm_name}",
                table_name="transfer_history",
                record_id=transfer.id
            )

        db.session.commit()
        flash(f'Transfer for animal "{animal.name}" approved successfully. Moved to {target_farm.farm_name}.', 'success')

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error approving transfer for animal {animal_id}: {str(e)}", exc_info=True)
        flash(f'Error approving transfer: {str(e)}', 'danger')

    return redirect(url_for('view_transfer_requests'))

@app.route('/admin/reject_transfer/<int:animal_id>')
def admin_reject_transfer(animal_id):
    if not session.get('is_admin'):
        abort(403)
    
    try:
        animal = Animal.query.get_or_404(animal_id)
        
        # Get ALL pending transfer requests for this animal
        pending_transfers = TransferHistory.query.filter_by(
            animal_id=animal_id,
            status='pending'
        ).all()

        # Update all pending transfer records for this animal
        for transfer in pending_transfers:
            transfer.status = 'rejected'
            transfer.approved_by = session['user_id']
            transfer.approval_date = datetime.now(timezone.utc)
        
        animal.transfer_request = None
        animal.status = 'approved'
        db.session.commit()
        flash('Transfer rejected', 'info')
    except Exception as e:
        db.session.rollback()
        flash(f'Error rejecting transfer: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/transfer_requests')
@login_required
@admin_required
def view_transfer_requests():
    pending_transfers = TransferHistory.query.filter_by(status='pending') \
        .order_by(TransferHistory.id.desc()).all()

    history_transfers = TransferHistory.query.filter(TransferHistory.status != 'pending') \
        .order_by(TransferHistory.id.desc()).all()

    return render_template('admin_transfer_requests.html',
                           pending_transfers=pending_transfers,
                           history_transfers=history_transfers)

@app.route('/admin/approve_transfer/<int:transfer_id>', methods=['POST'])
@admin_required
def approve_transfer(transfer_id):
    transfer = TransferHistory.query.options(
        db.joinedload(TransferHistory.animal),
        db.joinedload(TransferHistory.from_farm),
        db.joinedload(TransferHistory.to_farm)
    ).get_or_404(transfer_id)

    if transfer.status != 'pending':
        flash('Transfer already processed', 'warning')
        return redirect(url_for('view_transfer_requests'))

    try:
        # Approve the transfer
        transfer.status = 'approved'
        transfer.approved_by = current_user.id
        transfer.approval_date = datetime.now(timezone.utc)

        # Update the animal's farm and status
        transfer.animal.farm_id = transfer.to_farm_id
        transfer.animal.status = 'approved'
        transfer.animal.transfer_request = None

        # Generate the certificate buffer
        pdf_buffer = generate_transfer_certificate(transfer)

        # Ensure directory exists
        cert_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], "certificates")
        os.makedirs(cert_folder, exist_ok=True)

        # Save to disk and assign path
        certificate_filename = f"transfer_certificate_{transfer.id}.pdf"
        certificate_path = os.path.join("certificates", certificate_filename)
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], certificate_path)

        with open(full_path, "wb") as f:
            f.write(pdf_buffer.getvalue())

        transfer.certificate_path = certificate_path

        db.session.commit()

        flash(f'Transfer for "{transfer.animal.name}" approved and certificate generated.', 'success')
        return redirect(url_for('view_transfer_requests'))

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Transfer approval failed: {str(e)}")
        flash('Error approving transfer', 'danger')
        return redirect(url_for('view_transfer_requests'))


@app.route('/download_certificate/<int:transfer_id>')
@login_required
def download_certificate(transfer_id):
    transfer = TransferHistory.query.get_or_404(transfer_id)

    if not transfer.certificate_path:
        abort(404, description="Certificate not found")

    upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
    cert_path = upload_dir / transfer.certificate_path

    if not cert_path.exists():
        abort(404, description="Certificate file missing")

    return send_from_directory(
        upload_dir,
        transfer.certificate_path,
        as_attachment=True,
        download_name=f"transfer_certificate_{transfer.id}.pdf"
    )


@app.route('/generate_animal_pdf/<int:animal_id>')  # Changed the route pattern
@admin_required
def generate_animal_pdf(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farm = animal.farm
    
    # Create buffer for PDF
    buffer = BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                          rightMargin=36, leftMargin=36,
                          topMargin=36, bottomMargin=36)
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Content
    story = []
    
    # Title
    story.append(Paragraph("Animal Registration Certificate", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Photos
    photos = []
    if animal.photo1_path:
        try:
            img_path = os.path.join(current_app.root_path, 'static/uploads', animal.photo1_path)
            img1 = Image(img_path, width=2.5*inch, height=2.5*inch)
            photos.append(img1)
        except Exception as e:
            current_app.logger.error(f"Error loading photo1: {e}")
            
    if animal.photo2_path:
        try:
            img_path = os.path.join(current_app.root_path, 'static/uploads', animal.photo2_path)
            img2 = Image(img_path, width=2.5*inch, height=2.5*inch)
            photos.append(img2)
        except Exception as e:
            current_app.logger.error(f"Error loading photo2: {e}")
    
    if photos:
        photo_table = Table([photos], colWidths=[2.5*inch]*len(photos))
        story.append(photo_table)
        story.append(Spacer(1, 12))
    
    # Details
    details = [
        ["Animal Name:", animal.name],
        ["Type:", animal.animal_type.capitalize()],
        ["Gender:", animal.gender.capitalize()],
        ["Date of Birth:", animal.dob.strftime('%Y-%m-%d') if animal.dob else "Unknown"],
        ["Registration Date:", animal.registration_date.strftime('%Y-%m-%d')],
        ["Status:", animal.status.capitalize()],
        ["Farm:", farm.farm_name],
        ["Owner:", farm.owner.full_name]
    ]
    
    table = Table(details, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
        ('ALIGN', (0,0), (0,-1), 'RIGHT'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
    ]))
    
    story.append(table)
    
    # Build PDF
    doc.build(story)
    
    # Return response
    pdf = buffer.getvalue()
    buffer.close()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=animal_{animal.id}_record.pdf'
    return response

@app.route('/admin/reject_transfer/<int:transfer_id>', methods=['POST'])
@login_required
@admin_required
def reject_transfer(transfer_id):
    try:
        transfer = TransferHistory.query.get_or_404(transfer_id)
        
        if transfer.status != 'pending':
            flash('This transfer has already been processed', 'warning')
            return redirect(url_for('view_transfer_requests'))
        
        # Reject the transfer
        transfer.status = 'rejected'
        transfer.approved_by = current_user.id
        transfer.approval_date = datetime.now(timezone.utc)
        
        # Update animal status but keep it in original farm
        transfer.animal.status = 'approved'  # Change from transfer_pending to approved
        transfer.animal.transfer_request = None  # Clear the transfer request
        
        # Log the action
        current_user.log_action(
            action=f"Rejected transfer of animal {transfer.animal.name} to {transfer.to_farm.farm_name}",
            table_name="transfer_history",
            record_id=transfer.id,
            details=request.form.get('rejection_reason', 'No reason provided')
        )
        
        db.session.commit()
        flash('Transfer rejected', 'info')
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error rejecting transfer: {str(e)}", exc_info=True)
        flash(f'Error rejecting transfer: {str(e)}', 'danger')
    
    return redirect(url_for('view_transfer_requests'))

@app.route('/admin/transfer_history')
def admin_transfer_history():
    if not session.get('is_admin'):
        abort(403)
    
    transfers = TransferHistory.query.options(
        db.joinedload(TransferHistory.animal),
        db.joinedload(TransferHistory.from_farm),
        db.joinedload(TransferHistory.to_farm),
        db.joinedload(TransferHistory.initiator),
        db.joinedload(TransferHistory.approver)
    ).order_by(TransferHistory.transfer_date.desc()).all()
    
    return render_template('admin_transfer_history.html', transfers=transfers)

@app.route('/admin/edit_animal_name/<int:animal_id>', methods=['GET', 'POST'])
def admin_edit_animal_name(animal_id):
    if not session.get('is_admin'):
        abort(403)
    
    animal = Animal.query.get_or_404(animal_id)
    
    if request.method == 'POST':
        new_name = request.form['new_name'].strip()
        if not new_name:
            flash('Animal name cannot be empty', 'error')
            return redirect(url_for('admin_edit_animal_name', animal_id=animal_id))
        
        animal.name = new_name
        db.session.commit()
        flash('Animal name updated successfully', 'success')
        return redirect(url_for('admin_farm_details', farm_id=animal.farm_id))
    
    return render_template('admin_edit_animal_name.html', animal=animal)

@app.route('/user/transfer_history')
def user_transfer_history():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    user_farms = Farm.query.filter_by(user_id=session['user_id']).all()
    farm_ids = [farm.farm_id for farm in user_farms]
    
    transfers = TransferHistory.query.options(
        db.joinedload(TransferHistory.animal),
        db.joinedload(TransferHistory.from_farm),
        db.joinedload(TransferHistory.to_farm),
        db.joinedload(TransferHistory.initiator),
        db.joinedload(TransferHistory.approver)
    ).filter(
        (TransferHistory.transferred_by == session['user_id']) |
        (TransferHistory.from_farm_id.in_(farm_ids)) |
        (TransferHistory.to_farm_id.in_(farm_ids))
    ).order_by(TransferHistory.transfer_date.desc()).all()
    
    return render_template('user_transfer_history.html', transfers=transfers)

# Animal routes
@app.route('/view_animal/<int:animal_id>')
@login_required  # Ensures user is logged in
def view_animal(animal_id):
    try:
        # Get animal and farm with error handling
        animal = Animal.query.get_or_404(animal_id)
        farm = Farm.query.get_or_404(animal.farm_id)
        
        # Helper function to get photo URLs
        def get_photo_url(photo_path):
            if photo_path:
                photo_path = photo_path.replace('\\', '/')
                full_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_path)
                if os.path.exists(full_path):
                    return url_for('uploaded_file', filename=photo_path)
            return None

        # Determine which template to use
        template = 'admin_view_animal.html' if current_user.is_admin else 'view_animal.html'
        
        # Authorization checks
        if current_user.is_admin:
            # Admin can view any animal
            return render_template(template,
                                animal=animal,
                                farm=farm,
                                photo1_url=get_photo_url(animal.photo1_path),
                                photo2_url=get_photo_url(animal.photo2_path))
        
        elif farm.owner_id == current_user.id:
            # Owner can view their animals if approved
            if animal.status == 'approved':
                return render_template(template,
                                    animal=animal,
                                    farm=farm,
                                    photo1_url=get_photo_url(animal.photo1_path),
                                    photo2_url=get_photo_url(animal.photo2_path))
            else:
                flash('This animal is pending approval', 'warning')
                return redirect(url_for('user_dashboard'))
        
        else:
            flash('You can only view animals from your own farm', 'error')
            return redirect(url_for('user_dashboard'))

    except Exception as e:
        app.logger.error(f"Error viewing animal {animal_id}: {str(e)}")
        flash('Error viewing animal details', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/animal_certificate/<int:animal_id>')
@login_required
@admin_required
def animal_certificate(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farm = Farm.query.get_or_404(animal.farm_id)

    if animal.status != 'approved':
        flash('Only approved animals can generate certificates', 'error')
        return redirect(url_for('admin_farm_details', farm_id=farm.id))

    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                                rightMargin=36, leftMargin=36,
                                topMargin=36, bottomMargin=36)

        styles = getSampleStyleSheet()
        heading_style = styles['Heading2']
        elements = []

        # ======== Certificate Title and Ref ID ==========
        elements.append(Paragraph("<b>Animal Birth Certificate</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"<b>Certificate Reference ID:</b> #{animal.id}", heading_style))
        elements.append(Spacer(1, 20))

        # ========== Farm Details ================
        farm_data = [
            ["Farm Name:", farm.farm_name],
            ["Location:", farm.location],
            ["Contact Info:", farm.contact_info],
            ["Owner:", farm.owner.full_name]
        ]

        # Add logo if available
        if farm.logo_path:
            logo_path = os.path.join(current_app.config['UPLOAD_FOLDER'], farm.logo_path)
            if os.path.exists(logo_path):
                try:
                    logo_img = Image(logo_path, width=1.2*inch, height=1.2*inch)
                    farm_data.append(["Logo:", logo_img])
                except Exception as e:
                    current_app.logger.warning(f"Logo load failed: {e}")

        farm_table = Table(farm_data, colWidths=[2*inch, 4*inch])
        farm_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(Paragraph("Farm Information", heading_style))
        elements.append(farm_table)
        elements.append(Spacer(1, 20))

        # ========== Animal Photos ================
        photos = []
        for path in [animal.photo1_path, animal.photo2_path]:
            if path:
                img_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path)
                if os.path.exists(img_path):
                    try:
                        img = Image(img_path, width=2.2*inch, height=2.2*inch)
                        photos.append(img)
                    except Exception as e:
                        current_app.logger.warning(f"Photo load failed: {e}")

        if photos:
            photo_table = Table([photos])
            photo_table.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER')]))
            elements.append(Paragraph("Animal Photos", heading_style))
            elements.append(photo_table)
            elements.append(Spacer(1, 20))

        # ========== Animal Details ================
        details = [
            ["Name:", animal.name],
            ["Type:", animal.animal_type.capitalize()],
            ["Gender:", animal.gender.capitalize()],
            ["Dress Color:", animal.dress_color or "Unknown"],
            ["Date of Birth:", animal.dob.strftime('%Y-%m-%d') if animal.dob else "Unknown"],
            ["Father Lineage:", animal.father_lineage or "Unknown"],
            ["Mother Lineage:", animal.mother_lineage or "Unknown"],
            ["Registration Date:", animal.registration_date.strftime('%Y-%m-%d') if animal.registration_date else "Unknown"],
            ["Status:", animal.status.capitalize()]
        ]

        animal_table = Table(details, colWidths=[2*inch, 4*inch])
        animal_table.setStyle(TableStyle([
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(Paragraph("Animal Information", heading_style))
        elements.append(animal_table)

        # ========== Watermark and Background ============
        def add_watermark_and_style(canvas_obj, doc):
            # Light blue background
            canvas_obj.setFillColorRGB(0.94, 0.97, 1)
            canvas_obj.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)

            # Watermark
            canvas_obj.setFont("Helvetica-Bold", 40)
            canvas_obj.setFillColorRGB(0.7, 0.7, 0.7, alpha=0.2)
            canvas_obj.saveState()
            canvas_obj.translate(300, 400)
            canvas_obj.rotate(45)
            canvas_obj.drawCentredString(0, 0, "FARM REGISTERED")
            canvas_obj.restoreState()

        doc.build(elements, onFirstPage=add_watermark_and_style)

        buffer.seek(0)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"animal_certificate_{animal.id}.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        current_app.logger.error(f"PDF generation error: {str(e)}")
        flash('Error generating certificate', 'error')
        return redirect(url_for('admin_farm_details', farm_id=farm.id))

@app.route('/register/farm', methods=['GET', 'POST'])
@login_required
def register_farm():
    # Check if user already has a farm
    existing_farm = Farm.query.filter_by(owner_id=current_user.id).first()
    if existing_farm:
        flash('You already have a registered farm', 'warning')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            farm_name = request.form.get('farm_name')
            location = request.form.get('location')
            contact_info = request.form.get('contact_info')

            if not all([farm_name, location, contact_info]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register_farm'))

            new_farm = Farm(
                owner_id=current_user.id,
                farm_name=farm_name,
                location=location,
                contact_info=contact_info,
                status='pending'
            )
            db.session.add(new_farm)
            db.session.commit()

            flash('Farm registration submitted for approval', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash('Error registering farm: ' + str(e), 'danger')

    return render_template('register_farm.html')

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    # Get user's farm with error handling
    farm = Farm.query.filter_by(owner_id=current_user.id).first()
    
    if not farm:
        flash('Please register your farm first', 'warning')
        return redirect(url_for('register_farm'))
    
    # Get registration date or use current time if not set
    registration_date = getattr(farm, 'registration_date', datetime.now(timezone.utc))
    
    # Paginate animals
    page = request.args.get('page', 1, type=int)
    animals = Animal.query.filter_by(farm_id=farm.id)\
               .order_by(Animal.registration_date.desc())\
               .paginate(page=page, per_page=10, error_out=False)
    
    return render_template('user_dashboard.html',
                         farm=farm,
                         animals=animals,
                         current_date=datetime.now(timezone.utc).date())

@app.route('/register_animal/<int:farm_id>', methods=['GET', 'POST'])
@login_required
def register_animal(farm_id):
    farm = Farm.query.get_or_404(farm_id)
    
    # Verify ownership and farm status
    if farm.owner_id != current_user.id:
        flash("You can only register animals for your own farm", "danger")
        return redirect(url_for('user_dashboard'))
    
    if farm.status != 'approved':
        flash("Your farm must be approved before registering animals", "warning")
        return redirect(url_for('user_dashboard'))

    form = AnimalRegistrationForm()
    
    if form.validate_on_submit():
        try:
            # File handling
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
            animal_name = secure_filename(form.name.data)
            photo_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'animal_photos')
            os.makedirs(photo_dir, exist_ok=True)
            
            # Process photos with validation
            photo1 = form.photo1.data
            if not photo1 or not allowed_file(photo1.filename):
                flash('First photo is required and must be a valid image', 'danger')
                return redirect(url_for('register_animal', farm_id=farm_id))
                
            photo1_filename = f"{animal_name}_side_{timestamp}{os.path.splitext(photo1.filename)[1]}"
            photo1_path = os.path.join('animal_photos', photo1_filename)
            photo1.save(os.path.join(current_app.config['UPLOAD_FOLDER'], photo1_path))
            
            photo2 = form.photo2.data
            photo2_path = None
            if photo2 and photo2.filename:
                if not allowed_file(photo2.filename):
                    flash('Second photo must be a valid image', 'danger')
                    return redirect(url_for('register_animal', farm_id=farm_id))
                photo2_filename = f"{animal_name}_front_{timestamp}{os.path.splitext(photo2.filename)[1]}"
                photo2_path = os.path.join('animal_photos', photo2_filename)
                photo2.save(os.path.join(current_app.config['UPLOAD_FOLDER'], photo2_path))
            
            # Create animal
            animal = Animal(
                name=form.name.data,
                animal_type=form.animal_type.data,
                gender=form.gender.data,
                dob=form.dob.data,
                dress_color=form.dress_color.data,
                father_lineage=form.father_lineage.data,
                mother_lineage=form.mother_lineage.data,
                photo1_path=photo1_path,
                photo2_path=photo2_path,
                farm_id=farm.id,
                status='pending'
            )
            
            db.session.add(animal)
            
            # Log the registration
            current_user.log_action(
                action=f"Registered new animal: {animal.name}",
                table_name="animals",
                record_id=animal.id
            )
            
            db.session.commit()
            
            flash('Animal registered successfully! Awaiting admin approval.', 'success')
            return redirect(url_for('user_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            # Clean up uploaded files if error occurred
            for photo_path in [photo1_path, photo2_path]:
                if photo_path:
                    try:
                        os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], photo_path))
                    except:
                        pass
            
            current_app.logger.error(f"Registration error: {str(e)}", exc_info=True)
            flash(f'Registration failed: {str(e)}', 'danger')

    return render_template('register_animal.html', form=form, farm=farm)

@app.route('/admin/edit_farm/<int:farm_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_farm(farm_id):
    farm = Farm.query.get_or_404(farm_id)
    owner = User.query.get_or_404(farm.owner_id)
    form = FarmEditForm(obj=farm)
    form.owner_name.data = owner.full_name  # Pre-populate owner name
    
    if form.validate_on_submit():
        try:
            # Update farm details
            farm.farm_name = form.farm_name.data
            farm.location = form.location.data
            farm.contact_info = form.contact_info.data
            owner.full_name = form.owner_name.data
            
            # Handle logo upload
            if form.logo.data:
                # Delete old logo if exists
                if farm.logo_path:
                    old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], farm.logo_path)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                # Save new logo
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
                filename = f"{secure_filename(form.farm_name.data)}_{timestamp}{os.path.splitext(form.logo.data.filename)[1]}"
                logo_path = os.path.join('logos', filename)
                os.makedirs(os.path.join(current_app.config['UPLOAD_FOLDER'], 'logos'), exist_ok=True)
                form.logo.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], logo_path))
                farm.logo_path = logo_path
            
            db.session.commit()
            flash('Farm updated successfully', 'success')
            return redirect(url_for('admin_farm_details', farm_id=farm.id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating farm: {str(e)}", exc_info=True)
            flash(f'Error updating farm: {str(e)}', 'error')
    
    return render_template('admin_edit_farm.html',
                         farm=farm,
                         owner=owner,
                         form=form)

@app.route('/admin/edit_animal/<int:animal_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farms = Farm.query.filter_by(status='approved').all()
    form = AnimalRegistrationForm(obj=animal)
    
    if form.validate_on_submit():
        try:
            # Update basic fields
            animal.name = form.name.data
            animal.animal_type = form.animal_type.data
            animal.gender = form.gender.data
            animal.dob = form.dob.data
            animal.dress_color = form.dress_color.data
            animal.father_lineage = form.father_lineage.data
            animal.mother_lineage = form.mother_lineage.data
            
            # Handle photo uploads
            photo_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'animal_photos')
            os.makedirs(photo_dir, exist_ok=True)
            
            if form.photo1.data:
                # Delete old photo if exists
                if animal.photo1_path:
                    old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], animal.photo1_path)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                # Save new photo
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
                filename = f"{secure_filename(form.name.data)}_side_{timestamp}{os.path.splitext(form.photo1.data.filename)[1]}"
                photo_path = os.path.join('animal_photos', filename)
                form.photo1.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], photo_path))
                animal.photo1_path = photo_path
            
            if form.photo2.data:
                # Delete old photo if exists
                if animal.photo2_path:
                    old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], animal.photo2_path)
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                # Save new photo
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
                filename = f"{secure_filename(form.name.data)}_front_{timestamp}{os.path.splitext(form.photo2.data.filename)[1]}"
                photo_path = os.path.join('animal_photos', filename)
                form.photo2.data.save(os.path.join(current_app.config['UPLOAD_FOLDER'], photo_path))
                animal.photo2_path = photo_path
            
            db.session.commit()
            flash('Animal updated successfully', 'success')
            return redirect(url_for('admin_farm_details', farm_id=animal.farm_id))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error updating animal: {str(e)}", exc_info=True)
            flash(f'Error updating animal: {str(e)}', 'error')
    
    return render_template('admin_edit_animal.html',
                         animal=animal,
                         farms=farms,
                         form=form)

@app.route('/transfer_animal/<int:animal_id>', methods=['GET', 'POST'])
@login_required
def transfer_animal(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    current_farm = Farm.query.get_or_404(animal.farm_id)

    # Ensure the logged-in user owns the farm
    if current_farm.owner_id != current_user.id:
        flash('You can only transfer animals from your own farms', 'danger')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        try:
            target_farm_id = request.form['target_farm']
            target_farm = Farm.query.get_or_404(target_farm_id)

            # Create a transfer record
            transfer = TransferHistory(
                animal_id=animal.id,
                from_farm_id=current_farm.id,
                to_farm_id=target_farm.id,
                transferred_by=current_user.id,
                status='pending'
            )
            db.session.add(transfer)

            # Update animal status
            animal.transfer_request = target_farm.id
            animal.status = 'transfer_pending'

            db.session.commit()
            flash(f'Transfer request for "{animal.name}" has been sent to admin for approval.', 'success')
            return redirect(url_for('user_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing transfer request: {str(e)}', 'danger')
            return redirect(url_for('transfer_animal', animal_id=animal.id))

    # Show list of approved farms excluding current farm
    all_farms = Farm.query.filter(
        Farm.status == 'approved',
        Farm.id != current_farm.id
    ).all()

    return render_template('transfer_animal.html',
                           animal=animal,
                           current_farm=current_farm,
                           all_farms=all_farms)

@app.route('/some/action')
@login_required
def some_action():
    try:
        # Business logic here
        current_user.log_action(
            action="Performed some action",
            table_name="some_table",
            record_id=123,
            details="Additional details here"
        )
        db.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Action failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
