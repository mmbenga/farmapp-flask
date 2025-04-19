import os
from datetime import datetime, timezone
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import current_app
import logging
from fpdf import FPDF
from PIL import Image
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.units import inch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def create_upload_folders(app):
    try:
        upload_dir = Path(app.config['UPLOAD_FOLDER'])
        (upload_dir / 'logos').mkdir(parents=True, exist_ok=True)
        (upload_dir / 'animal_photos').mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Upload directories created at: {upload_dir}")
        return True
    except Exception as e:
        logger.error(f"Failed to create upload directories: {str(e)}")
        return False

def save_uploaded_file(file, subfolder, prefix):
    if not file or file.filename == '' or not allowed_file(file.filename):
        logger.warning(f"Invalid or empty file upload attempt: {file.filename}")
        return None
    try:
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        ext = Path(file.filename).suffix.lower()
        filename = f"{secure_filename(prefix)}_{timestamp}{ext}"
        upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
        save_dir = upload_dir / subfolder
        save_dir.mkdir(parents=True, exist_ok=True)
        relative_path = f"{subfolder}/{filename}"
        file.save(upload_dir / relative_path)
        logger.info(f"File saved to: {relative_path}")
        return relative_path
    except Exception as e:
        logger.error(f"Error saving file: {str(e)}")
        return None

def validate_image_dimensions(file, min_width=300, min_height=300):
    try:
        with Image.open(file) as img:
            width, height = img.size
            return width >= min_width and height >= min_height
    except Exception as e:
        logger.error(f"Error validating image dimensions: {str(e)}")
        return False

def delete_animal_photos(animal):
    try:
        upload_dir = Path(current_app.config['UPLOAD_FOLDER'])
        for photo_attr in ['photo1_path', 'photo2_path']:
            photo = getattr(animal, photo_attr)
            if photo:
                path = upload_dir / photo
                if path.exists():
                    path.unlink()
    except Exception as e:
        logger.error(f"Error deleting photos: {str(e)}")

def generate_transfer_certificate(transfer):
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
                                rightMargin=36, leftMargin=36,
                                topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=16, alignment=1, spaceAfter=12)
        heading_style = ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=12, spaceAfter=6)

        elements = []
        elements.append(Paragraph("ANIMAL TRANSFER CERTIFICATE", title_style))
        elements.append(Spacer(1, 6))

        # Farm Transfer Details
        farm_data = [
            ["From Farm:", transfer.from_farm.farm_name],
            ["Location:", transfer.from_farm.location],
            ["Contact:", transfer.from_farm.contact_info],
            ["To Farm:", transfer.to_farm.farm_name],
            ["Location:", transfer.to_farm.location],
            ["Contact:", transfer.to_farm.contact_info]
        ]
        farm_table = Table(farm_data, colWidths=[2*inch, 4*inch])
        farm_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,5), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        elements.append(Paragraph("Transfer Details", heading_style))
        elements.append(farm_table)
        elements.append(Spacer(1, 8))

        # Animal Details
        animal = transfer.animal
        animal_data = [
            ["Name:", animal.name],
            ["Type:", animal.animal_type.capitalize()],
            ["Gender:", animal.gender.capitalize()],
            ["DOB:", animal.dob.strftime('%Y-%m-%d') if animal.dob else "Unknown"],
            ["Registration:", animal.registration_date.strftime('%Y-%m-%d')],
            ["Markings:", animal.dress_color or "None"]
        ]
        animal_table = Table(animal_data, colWidths=[2*inch, 4*inch])
        animal_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,5), colors.lightblue),
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        elements.append(Paragraph("Animal Information", heading_style))
        elements.append(animal_table)
        elements.append(Spacer(1, 8))

        # Animal Photos
        photo_paths = []
        for path in [animal.photo1_path, animal.photo2_path]:
            if path:
                img_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path)
                if os.path.exists(img_path):
                    try:
                        img = RLImage(img_path, width=2*inch, height=2*inch)
                        photo_paths.append(img)
                    except Exception as e:
                        logger.warning(f"Image load failed: {str(e)}")

        if photo_paths:
            elements.append(Paragraph("Animal Photos", heading_style))
            photo_table = Table([photo_paths], colWidths=[2*inch]*len(photo_paths))
            photo_table.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ]))
            elements.append(photo_table)
            elements.append(Spacer(1, 8))

        # Transfer Authorization
        transfer_data = [
            ["Transfer Date:", transfer.transfer_date.strftime('%Y-%m-%d %H:%M')],
            ["Approved By:", transfer.approver.full_name if transfer.approver else "System"],
            ["Approval Date:", datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')]
        ]
        transfer_table = Table(transfer_data, colWidths=[2*inch, 4*inch])
        transfer_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        elements.append(Paragraph("Transfer Authorization", heading_style))
        elements.append(transfer_table)
        elements.append(Spacer(1, 8))

        elements.append(Paragraph("OFFICIALLY RECORDED", styles['Heading3']))
        elements.append(Paragraph("Farm Registration System", styles['Normal']))

        doc.build(elements)
        buffer.seek(0)
        return buffer
    except Exception as e:
        logger.error(f"Error generating certificate: {str(e)}")
        raise

def generate_animal_pdf(animal, farm):
    """Generate PDF certificate for an animal using FPDF"""
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Title
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="Animal Registration Certificate", ln=1, align='C')
        pdf.ln(10)

        # Farm logo
        if farm.logo_path:
            logo_path = Path(current_app.config['UPLOAD_FOLDER']) / farm.logo_path
            if logo_path.exists():
                pdf.image(str(logo_path), x=10, y=20, w=30)

        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Animal Name: {animal.name}", ln=1)
        pdf.cell(200, 10, txt=f"Type: {animal.animal_type.title()}", ln=1)
        pdf.cell(200, 10, txt=f"Gender: {animal.gender.title()}", ln=1)
        pdf.cell(200, 10, txt=f"Date of Birth: {animal.dob.strftime('%Y-%m-%d') if animal.dob else 'N/A'}", ln=1)
        pdf.cell(200, 10, txt=f"Father Lineage: {animal.father_lineage or 'Unknown'}", ln=1)
        pdf.cell(200, 10, txt=f"Mother Lineage: {animal.mother_lineage or 'Unknown'}", ln=1)
        pdf.cell(200, 10, txt=f"Dress Color: {animal.dress_color or 'N/A'}", ln=1)
        pdf.cell(200, 10, txt=f"Farm: {farm.farm_name}", ln=1)
        pdf.cell(200, 10, txt=f"Location: {farm.location}", ln=1)
        pdf.ln(10)

        # Animal Photos
        photo_y = 100
        if animal.photo1_path:
            photo1_path = Path(current_app.config['UPLOAD_FOLDER']) / animal.photo1_path
            if photo1_path.exists():
                with Image.open(photo1_path) as img:
                    img.thumbnail((150, 150))
                    temp_path = photo1_path.with_name(f"temp_{photo1_path.name}")
                    img.save(temp_path)
                    pdf.image(str(temp_path), x=30, y=photo_y, w=60)
                    temp_path.unlink()

        if animal.photo2_path:
            photo2_path = Path(current_app.config['UPLOAD_FOLDER']) / animal.photo2_path
            if photo2_path.exists():
                with Image.open(photo2_path) as img:
                    img.thumbnail((150, 150))
                    temp_path = photo2_path.with_name(f"temp_{photo2_path.name}")
                    img.save(temp_path)
                    pdf.image(str(temp_path), x=110, y=photo_y, w=60)
                    temp_path.unlink()

        # Footer
        pdf.set_y(-15)
        pdf.set_font("Arial", 'I', 8)
        pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d')}", 0, 0, 'C')

        return pdf.output(dest='S').encode('latin1')

    except Exception as e:
        logger.error(f"Error generating animal PDF: {str(e)}")
        raise
