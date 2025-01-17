from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, Email, Regexp, EqualTo
import requests


class SignupForm(FlaskForm):
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


class LoginForm(FlaskForm):
    email = EmailField(validators=[
        InputRequired(),
        Email(message="Invalid email address"),
        Length(min=7, max=1000)
    ], render_kw={"placeholder": "Email Address"})

    password = PasswordField(validators=[InputRequired()],
                             render_kw={"placeholder": "Password"})

    submit = SubmitField("Log In", render_kw={"class": "button"})


class RecoveryForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Length(
        min=7, max=1000)], render_kw={"placeholder": "Email Address"})
    submit = SubmitField("Send Code", render_kw={"class": "button"})


class VerifyForm(FlaskForm):
    code = IntegerField(validators=[InputRequired()], render_kw={
                        "placeholder": "Verification Code"})
    submit = SubmitField("Verify", render_kw={"class": "button"})


class ResetPasswordForm(FlaskForm):
    newpassword = StringField(validators=[InputRequired()], render_kw={
                              "placeholder": "New Password"})
    submit = SubmitField("Save Changes", render_kw={"class": "button"})


def sendMail(target, subject, message):
    url = "https://rapidprod-sendgrid-v1.p.rapidapi.com/mail/send"

    payload = {
        "personalizations": [
            {
                "to": [{"email": target}],
                "subject": subject
            }
        ],
        "from": {"email": "StockSensie@bot.ai"},
        "content": [
            {
                "type": "text/html",
                "value": message
            }
        ]
    }
    headers = {
        'x-rapidapi-key': "d4d05acf85msh97c5505d255de23p185982jsn3c9c5957c2d2",
        'x-rapidapi-host': "rapidprod-sendgrid-v1.p.rapidapi.com",
        'Content-Type': "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        print("Email sent successfully!")
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error sending email: {e}")
        # Print the API response for debugging
        print(f"Response: {response.text}")
        return None
