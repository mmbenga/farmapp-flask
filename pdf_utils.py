from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime

def generate_animal_pdf(animal, farm, is_admin=False):
    """Generate PDF certificate for animal registration"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Modify existing styles instead of adding new ones
    styles['Title'].fontSize = 18
    styles['Title'].alignment = 1  # Center alignment
    styles['Title'].spaceAfter = 12
    
    styles['Heading1'].fontSize = 14
    styles['Heading1'].alignment = 1
    styles['Heading1'].spaceAfter = 6
    
    story = []
    
    # Header
    title = "OFFICIAL ANIMAL REGISTRATION CERTIFICATE" if is_admin else "ANIMAL REGISTRATION RECORD"
    story.append(Paragraph(title, styles['Title']))
    
    if is_admin:
        story.append(Paragraph("Valid for Official Use Only", styles['Heading1']))
    
    # Farm Information
    story.append(Paragraph("FARM INFORMATION", styles['Heading1']))
    farm_data = [
        ["Farm Name:", farm.farm_name],
        ["Owner:", farm.owner.full_name],
        ["Location:", farm.location],
        ["Contact:", farm.contact_info]
    ]
    farm_table = Table(farm_data, colWidths=[1.5*inch, 4*inch])
    farm_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 12),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(farm_table)
    
    # Animal Information
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("ANIMAL DETAILS", styles['Heading1']))
    animal_data = [
        ["ID:", animal.animal_name],
        ["Date of Birth:", animal.dob.strftime('%Y-%m-%d')],
        ["Color:", animal.dress_color]
    ]
    animal_table = Table(animal_data, colWidths=[1.5*inch, 4*inch])
    story.append(animal_table)
    
    doc.build(story)
    buffer.seek(0)
    return buffer