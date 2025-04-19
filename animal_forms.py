# animal_forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, DateField, FileField, SubmitField
from wtforms.validators import DataRequired

class AnimalRegistrationForm(FlaskForm):
    name = StringField('Animal Name', validators=[DataRequired()])
    animal_type = SelectField('Animal Type', choices=[
        ('cattle', 'Cattle'), 
        ('ladoum', 'Ladoum'),
        ('sheep', 'Sheep'),
        ('goat', 'Goat'),
        ('pig', 'Pig'),
        ('poultry', 'Poultry')
    ], validators=[DataRequired()])
    gender = SelectField('Gender', choices=[
        ('male', 'Male'),
        ('female', 'Female')
    ], validators=[DataRequired()])
    breed = StringField('Breed')  # Explicitly included
    dob = DateField('Date of Birth', format='%Y-%m-%d')
    dress_color = StringField('Color/Markings')
    father_lineage = StringField('Father Lineage')
    mother_lineage = StringField('Mother Lineage')
    photo1 = FileField('Side View Photo', validators=[DataRequired()])
    photo2 = FileField('Front View Photo', validators=[DataRequired()])
    submit = SubmitField('Register Animal')

    def __repr__(self):
        return f"<AnimalRegistrationForm fields: {[field.name for field in self]}>"