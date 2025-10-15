import os
from pathlib import Path

class Config:
    SECRET_KEY = 'your-secret-key'  # Change for production
    
    # Changed from MySQL to SQLite
    BASE_DIR = Path(__file__).parent.resolve()
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR / "farm_registration.db"}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload configuration
    UPLOAD_FOLDER = BASE_DIR / 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # Subdirectories
    LOGO_FOLDER = 'logos'
    ANIMAL_PHOTOS_FOLDER = 'animal_photos'

    @classmethod
    def create_folders(cls):
        """Create required upload directories"""
        try:
            (cls.UPLOAD_FOLDER/cls.LOGO_FOLDER).mkdir(parents=True, exist_ok=True)
            (cls.UPLOAD_FOLDER/cls.ANIMAL_PHOTOS_FOLDER).mkdir(parents=True, exist_ok=True)
            print(f"✔ Upload directories created at: {cls.UPLOAD_FOLDER}")
        except Exception as e:
            print(f"✖ Error creating directories: {str(e)}")
            raise

# Initialize folders when config is loaded
Config.create_folders()