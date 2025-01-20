from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo
import requests
from dotenv import load_dotenv
import os

load_dotenv()  

api_key = os.getenv('SENDINBLUE_API_KEY')  

class BaseForm(FlaskForm):
    class Meta:
        csrf = True
        
class SignupForm(BaseForm):
    username = StringField(validators=[
        InputRequired(),
        Length(min=2, max=100),
        Regexp(
            r'^[\w]+$', message="Username must contain only letters, numbers, and underscores")
    ], render_kw={"placeholder": "Username"})

    email = EmailField(validators=[
        InputRequired(),
        Email(message="Invalid email address"),
        Length(min=7, max=1000)
    ], render_kw={"placeholder": "Email Address"})

    password = PasswordField(validators=[InputRequired()],
                             render_kw={
        "placeholder": "Password",
        "onkeyup": "updatePasswordRequirements(this.value)"
    })

    conpassword = PasswordField(validators=[InputRequired(), EqualTo('password', message='Passwords do not match')
                                            ],
                                render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField("Create Account", render_kw={"class": "button"})


class LoginForm(BaseForm):
    email = EmailField(validators=[
        InputRequired(),
        Email(message="Invalid email address"),
        Length(min=7, max=1000)
    ], render_kw={"placeholder": "Email Address"})

    password = PasswordField(validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField("Log In", render_kw={"class": "button"})


class RecoveryForm(BaseForm):
    email = EmailField(validators=[InputRequired(), Length(
        min=7, max=1000)], render_kw={"placeholder": "Email Address"})
    submit = SubmitField("Send Code", render_kw={"class": "button"})


class VerifyForm(BaseForm):
    code = IntegerField(validators=[InputRequired()], render_kw={
                        "placeholder": "Verification Code"})
    submit = SubmitField("Verify", render_kw={"class": "button"})


class ResetPasswordForm(BaseForm):
    newpassword = StringField(validators=[InputRequired()], render_kw={
                              "placeholder": "New Password"})
    submit = SubmitField("Save Changes", render_kw={"class": "button"})

class TotpForm(BaseForm):
    totp = StringField(validators=[
        InputRequired(),
        Length(min=6, max=6, message="TOTP code must be 6 digits"),
        Regexp(r'^[0-9]+$', message="TOTP code must contain only numbers")
    ], render_kw={"placeholder": "Enter 6-digit code"})
    
    submit = SubmitField("Verify", render_kw={"class": "button"})
    
def sendMail(target, subject, message):
    url = "https://api.sendinblue.com/v3/smtp/email"

    payload = {
        "sender": {"name": "StockSensie Bot", "email": "namezyasser3@gmail.com"},
        "to": [{"email": target}],
        "subject": subject,
        "htmlContent": message
    }
    
    headers = {
        "api-key": api_key,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error sending email: {e}")
        print(f"Response: {response.text}")
        return None
