from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SelectField, DateField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Optional, Length, Email, EqualTo, ValidationError
from datetime import datetime
from models import User, Farm  # Make sure to import Farm here

class AnimalRegistrationForm(FlaskForm):
    name = StringField('Animal Name', validators=[DataRequired()])
    animal_type = SelectField('Animal Type', 
                            choices=[('cattle', 'Cattle'), ('goat', 'Goat'), ('sheep', 'Sheep')],
                            validators=[DataRequired()])
    gender = SelectField('Gender', 
                        choices=[('male', 'Male'), ('female', 'Female')],
                        validators=[DataRequired()])
    dob = DateField('Date of Birth', format='%Y-%m-%d', validators=[Optional()])
    dress_color = StringField('Color/Markings', validators=[Optional()])
    father_lineage = StringField('Father Lineage', validators=[Optional()])
    mother_lineage = StringField('Mother Lineage', validators=[Optional()])
    photo1 = FileField('Side View Photo', validators=[DataRequired()])
    photo2 = FileField('Front View Photo', validators=[DataRequired()])
    submit = SubmitField('Register Animal')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=25, message='Username must be between 4-25 characters')
    ])
    full_name = StringField('Full Name', validators=[DataRequired()])
    contact_info = StringField('Contact Information', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    is_admin = SelectField('Role', 
                         choices=[(False, 'Regular User'), (True, 'Administrator')],
                         coerce=bool,
                         validators=[DataRequired()])
    farm_relation = SelectField('Farm Relationship', 
                              choices=[
                                  ('none', 'No Farm Association'),
                                  ('owner', 'Farm Owner'),
                                  ('worker', 'Farm Worker')
                              ],
                              validators=[Optional()])
    farm_id = SelectField('Select Farm', coerce=int, validators=[Optional()])
    submit = SubmitField('Create User')

    def __init__(self, *args, **kwargs):
        super(UserForm, self).__init__(*args, **kwargs)
        # Populate farm choices only if Farm model is available
        if 'Farm' in globals():
            self.farm_id.choices = [(0, '-- Select a Farm --')] + [
                (farm.id, farm.farm_name) 
                for farm in Farm.query.order_by(Farm.farm_name).all()
            ]
        else:
            self.farm_id.choices = [(0, '-- No Farms Available --')]

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class FarmEditForm(FlaskForm):
    farm_name = StringField('Farm Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Farm name must be between 2-100 characters')
    ])
    location = StringField('Location', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Location must be between 2-100 characters')
    ])
    contact_info = StringField('Contact Information', validators=[
        DataRequired(),
        Length(min=5, max=100, message='Contact info must be between 5-100 characters')
    ])
    owner_name = StringField('Owner Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message='Owner name must be between 2-100 characters')
    ])
    logo = FileField('Farm Logo', validators=[
        Optional(),
        FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Images only!')
    ])
    submit = SubmitField('Update Farm')