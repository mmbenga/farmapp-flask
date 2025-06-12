from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from flask import url_for, current_app
from pathlib import Path
import os
import logging
from datetime import datetime, timezone
from sqlalchemy import event
from sqlalchemy.orm import validates

db = SQLAlchemy()
logger = logging.getLogger(__name__)

# Association table for farm workers
farm_workers = db.Table('farm_workers',
    db.Column('farm_id', db.Integer, db.ForeignKey('farms.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120))
    contact_info = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    owned_farms = db.relationship(
        'Farm', 
        back_populates='owner',
        foreign_keys='[Farm.owner_id]',
        cascade='all, delete-orphan'
    )
    working_farms = db.relationship(
        'Farm',
        secondary=farm_workers,
        back_populates='workers'
    )
    initiated_transfers = db.relationship(
        'TransferHistory', 
        foreign_keys='[TransferHistory.transferred_by]',
        back_populates='initiator'
    )
    approved_transfers = db.relationship(
        'TransferHistory',
        foreign_keys='[TransferHistory.approved_by]',
        back_populates='approver'
    )
    audit_logs = db.relationship('AuditLog', back_populates='user')

    @validates('username')
    def validate_username(self, key, username):
        if len(username) < 4:
            raise ValueError("Username must be at least 4 characters")
        if not username.isalnum():
            raise ValueError("Username can only contain letters and numbers")
        return username.lower()

    def set_password(self, password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(char.isdigit() for char in password):
            raise ValueError("Password must contain at least one number")
        if not any(char.isupper() for char in password):
            raise ValueError("Password must contain at least one uppercase letter")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def log_action(self, action, table_name=None, record_id=None, details=None):
        log = AuditLog(
            user_id=self.id,
            action=action,
            table_name=table_name,
            record_id=record_id,
            details=details
        )
        db.session.add(log)
        return log

class Farm(db.Model):
    __tablename__ = 'farms'
    
    id = db.Column(db.Integer, primary_key=True)
    farm_name = db.Column(db.String(100), unique=True, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)
    logo_path = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending', index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    registration_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    owner = db.relationship(
        'User', 
        back_populates='owned_farms',
        foreign_keys=[owner_id]
    )
    workers = db.relationship(
        'User',
        secondary=farm_workers,
        back_populates='working_farms'
    )
    animals = db.relationship(
        'Animal', 
        back_populates='farm', 
        foreign_keys='[Animal.farm_id]',
        cascade='all, delete-orphan'
    )
    outgoing_transfers = db.relationship(
        'TransferHistory', 
        foreign_keys='[TransferHistory.from_farm_id]',
        back_populates='from_farm'
    )
    incoming_transfers = db.relationship(
        'TransferHistory', 
        foreign_keys='[TransferHistory.to_farm_id]',
        back_populates='to_farm'
    )

    @property
    def farm_id(self):
        return self.id
    
    @property
    def logo_url(self):
        if not self.logo_path:
            return url_for('static', filename='images/default-farm.png', _external=True)
        
        try:
            clean_path = self.logo_path.replace('\\', '/').replace('logos/', '')
            full_path = Path(current_app.config['UPLOAD_FOLDER']) / 'logos' / clean_path
            if not full_path.exists():
                current_app.logger.warning(f"Logo file not found at: {full_path}")
                return None
            return url_for('serve_logo', filename=clean_path, _external=True)
        except Exception as e:
            current_app.logger.error(f"Error generating logo URL: {str(e)}")
            return None

    @validates('farm_name')
    def validate_farm_name(self, key, farm_name):
        if len(farm_name) < 3:
            raise ValueError("Farm name must be at least 3 characters")
        return farm_name.strip()

    def __repr__(self):
        return f'<Farm {self.farm_name} (ID: {self.id})>'

class Animal(db.Model):
    __tablename__ = 'animals'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    animal_type = db.Column(db.String(80), nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending', index=True)
    dob = db.Column(db.Date)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    dress_color = db.Column(db.String(50))
    father_lineage = db.Column(db.String(120))
    mother_lineage = db.Column(db.String(120))
    photo1_path = db.Column(db.String(200))
    photo2_path = db.Column(db.String(200))
    farm_id = db.Column(db.Integer, db.ForeignKey('farms.id'))
    transfer_request = db.Column(db.Integer, db.ForeignKey('farms.id'), nullable=True)

    # Relationships
    farm = db.relationship('Farm', foreign_keys=[farm_id], back_populates='animals')
    transfer_farm = db.relationship('Farm', foreign_keys=[transfer_request])
    transfers = db.relationship('TransferHistory', back_populates='animal', cascade='all, delete-orphan')

    @property
    def age(self):
        if not self.dob:
            return "Unknown"
        today = datetime.now(timezone.utc).date()
        age_days = (today - self.dob).days
        
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

    @property
    def photo1_url(self):
        return self._generate_asset_url(self.photo1_path)

    @property
    def photo2_url(self):
        return self._generate_asset_url(self.photo2_path)

    def _generate_asset_url(self, asset_path):
        if not asset_path:
            return url_for('static', filename='images/default-animal.png', _external=True)
            
        try:
            clean_path = self._normalize_path(asset_path)
            return url_for('uploaded_file', filename=clean_path, _external=True)
        except Exception as e:
            logger.error(f"Error generating photo URL: {str(e)}")
            return None

    def _normalize_path(self, path):
        if not path:
            return None
        clean_path = path.replace('\\', '/').strip('/')
        return os.path.basename(clean_path)

    @validates('name')
    def validate_name(self, key, name):
        if len(name) < 2:
            raise ValueError("Animal name must be at least 2 characters")
        return name.strip()

    @validates('status')
    def validate_status(self, key, status):
        valid_statuses = ['pending', 'approved', 'rejected', 'transfer_pending']
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return status

    def __repr__(self):
        return f'<Animal {self.name} ({self.animal_type})>'

class TransferHistory(db.Model):
    __tablename__ = 'transfer_history'

    certificate_path = db.Column(db.String(255))
    id = db.Column(db.Integer, primary_key=True)
    animal_id = db.Column(db.Integer, db.ForeignKey('animals.id'), nullable=False)
    from_farm_id = db.Column(db.Integer, db.ForeignKey('farms.id'), nullable=False)
    to_farm_id = db.Column(db.Integer, db.ForeignKey('farms.id'), nullable=False)
    transferred_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending/approved/rejected
    notes = db.Column(db.Text)
    transfer_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    animal = db.relationship('Animal', back_populates='transfers')
    from_farm = db.relationship('Farm', foreign_keys=[from_farm_id], back_populates='outgoing_transfers')
    to_farm = db.relationship('Farm', foreign_keys=[to_farm_id], back_populates='incoming_transfers')
    initiator = db.relationship('User', foreign_keys=[transferred_by], back_populates='initiated_transfers')
    approver = db.relationship('User', foreign_keys=[approved_by], back_populates='approved_transfers')
    
    def approve(self, approver_id):
        self.status = 'approved'
        self.approved_by = approver_id
        self.approval_date = datetime.now(timezone.utc)
        self.animal.farm_id = self.to_farm_id
        self.animal.transfer_request = None
        self.animal.status = 'approved'

    def reject(self, approver_id):
        self.status = 'rejected'
        self.approved_by = approver_id
        self.approval_date = datetime.now(timezone.utc)
        self.animal.transfer_request = None
        self.animal.status = 'approved'

    @validates('status')
    def validate_status(self, key, status):
        valid_statuses = ['pending', 'approved', 'rejected']
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return status

    def __repr__(self):
        return f'<Transfer {self.animal_id} from {self.from_farm_id} to {self.to_farm_id}>'

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(255))
    table_name = db.Column(db.String(50))
    record_id = db.Column(db.Integer)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45))
    
    user = db.relationship('User', back_populates='audit_logs')

    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'

# Event listeners
@event.listens_for(Animal, 'after_delete')
def delete_animal_photos(mapper, connection, target):
    """Delete associated photos when animal is deleted"""
    try:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        for photo_path in [target.photo1_path, target.photo2_path]:
            if photo_path:
                full_path = os.path.join(upload_folder, photo_path)
                if os.path.exists(full_path):
                    os.remove(full_path)
    except Exception as e:
        logger.error(f"Error deleting animal photos: {str(e)}")

@event.listens_for(Farm, 'after_delete')
def delete_farm_logo(mapper, connection, target):
    """Delete logo file when farm is deleted"""
    try:
        if target.logo_path:
            full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], target.logo_path)
            if os.path.exists(full_path):
                os.remove(full_path)
    except Exception as e:
        logger.error(f"Error deleting farm logo: {str(e)}")