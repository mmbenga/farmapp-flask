# Import the app instance from app.py (or whatever your app entry file is)
from app import app

# Import the Animal model from models.py
from models import Animal

# Import the admin_required decorator from decorators.py
from decorators import admin_required

# Other necessary imports
from flask import make_response, current_app
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime
import os

@app.route('/animal/<int:animal_id>/generate_pdf')
@admin_required
def generate_animal_pdf(animal_id):
    animal = Animal.query.get_or_404(animal_id)
    farm = animal.farm
    
    # Create PDF buffer
    buffer = BytesIO()
    
    # Create PDF document with margins (borders)
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                          rightMargin=36, leftMargin=36,
                          topMargin=36, bottomMargin=36)
    
    # Custom styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Title', 
                            fontName='Helvetica-Bold', 
                            fontSize=18, 
                            alignment=1, 
                            spaceAfter=12))
    styles.add(ParagraphStyle(name='Header', 
                            fontName='Helvetica-Bold', 
                            fontSize=12, 
                            spaceAfter=6))
    
    # PDF content
    story = []
    
    # Add title
    story.append(Paragraph("Animal Registration Certificate", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Add animal photos if they exist
    photos = []
    if animal.photo1_path:
        try:
            img_path = os.path.join(current_app.root_path, 'static/uploads', animal.photo1_path)
            img1 = Image(img_path, width=2.5*inch, height=2.5*inch)
            photos.append(img1)
        except:
            pass
            
    if animal.photo2_path:
        try:
            img_path = os.path.join(current_app.root_path, 'static/uploads', animal.photo2_path)
            img2 = Image(img_path, width=2.5*inch, height=2.5*inch)
            photos.append(img2)
        except:
            pass
    
    if photos:
        photo_table = Table([photos], colWidths=[2.5*inch]*len(photos))
        story.append(photo_table)
        story.append(Spacer(1, 12))
    
    # Animal details
    details = [
        ["Animal Name:", animal.name],
        ["Animal Type:", animal.animal_type.capitalize()],
        ["Gender:", animal.gender.capitalize()],
        ["Date of Birth:", animal.dob.strftime('%Y-%m-%d') if animal.dob else "Unknown"],
        ["Registration Date:", animal.registration_date.strftime('%Y-%m-%d')],
        ["Status:", animal.status.capitalize()],
        ["Farm:", farm.farm_name],
        ["Location:", farm.location],
        ["Owner:", farm.owner.full_name]
    ]
    
    # Create table
    table = Table(details, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
        ('ALIGN', (0,0), (0,-1), 'RIGHT'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
    ]))
    
    story.append(table)
    story.append(Spacer(1, 24))
    
    # Add footer
    generated_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    story.append(Paragraph(f"Generated on: {generated_on}", styles['Normal']))
    
    # Build PDF
    doc.build(story)
    
    # Return PDF response
    pdf = buffer.getvalue()
    buffer.close()
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=animal_{animal.id}_record.pdf'
    return response
