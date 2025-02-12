import os
import re
from flask import Flask, session , render_template, redirect, request, url_for , jsonify,flash
from werkzeug.security import check_password_hash, generate_password_hash
import traceback

from form import *
import random
from flask_wtf import CSRFProtect
from flask_session import Session
from flask_talisman import Talisman
from flask_qrcode import QRcode
import pyotp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from bson.objectid import ObjectId
from functools import wraps
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
secret_key = os.urandom(12).hex()
app.config['SECRET_KEY'] = secret_key
app.config.update(
    SECRET_KEY = os.urandom(32),
    SESSION_PERMANENT = False,
    SESSION_TYPE = 'filesystem',
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1),
    # CSRF Configuration
    WTF_CSRF_ENABLED = True,
    WTF_CSRF_SECRET_KEY = os.urandom(32),
    WTF_CSRF_TIME_LIMIT = 3600,  # 1 hour in seconds
    # Session Cookie Settings
    SESSION_COOKIE_SECURE = False,  
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax',
    # Allow all IP addresses to access the app
    SERVER_NAME = None
)

# Initialize Session before other extensions
Session(app)

# Initialize CSRF protection with settings for cross-IP access
csrf = CSRFProtect()
csrf.init_app(app)

Talisman(app, 
    content_security_policy={
        'default-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'img-src': ["'self'", 'data:', '*'],
        'style-src': ["'self'", "'unsafe-inline'", 'https:', '*'],
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https:', '*'],
        'font-src': ["'self'", 'https:', 'data:', '*'],
        'connect-src': ["'self'", '*']
    },
    force_https=False,
    session_cookie_secure=False
)

bcrypt = Bcrypt(app)
QRcode(app)

# MongoDB connection
client = MongoClient('mongodb+srv://namezyasser3:admin@cluster0.ga0p0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client.recipes_manager


emailSent = False
code = ""
resetPass = False
emailPointed = ""
recFinished = False


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_session_valid():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def totp_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id' not in session:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))

        user = db.users.find_one({'_id': ObjectId(session['id'])})
        
        if not user:
            session.clear()
            flash('User not found', 'error')
            return redirect(url_for('login'))

        # Check if 2FA is enabled for user
        if user.get('totp_enabled', False):
            # Check if TOTP was verified in this session
            if not session.get('totp_verified', False):
                # Store original destination
                session['next_url'] = request.url
                flash('Please verify your 2FA code', 'warning')
                return redirect(url_for('verify_totp'))

        return f(*args, **kwargs)
    return decorated_function

def init_session(user_id):
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)
    session["id"] = str(user_id)
    session["login_time"] = datetime.utcnow().timestamp()

def is_session_valid():
    if "login_time" not in session:
        return False
    login_time = datetime.fromtimestamp(session["login_time"])
    return datetime.utcnow() - login_time < app.permanent_session_lifetime

@app.before_request
def before_request():
    if "id" in session and not is_session_valid():
        session.clear()
        return redirect(url_for('login'))

def check_password_requirements(password):
    requirements = {
        'length': len(password) >= 12,
        'uppercase': bool(re.search(r'[A-Z]', password)),
        'lowercase': bool(re.search(r'[a-z]', password)),
        'number': bool(re.search(r'\d', password)),
        'special': bool(re.search(r'[@$!%*#?&]', password))
    }
    return requirements

@app.route("/enable_totp", methods=["GET", "POST"])
@login_required
def enable_totp():
    form = TotpForm()  # Use the TotpForm for TOTP verification

    if request.method == "GET":
        # Generate new TOTP secret
        totp_secret = pyotp.random_base32()
        session['temp_totp_secret'] = totp_secret
        
        # Generate QR code URI
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=session.get("email"),
            issuer_name="Recipe Manager"
        )
        
        return render_template(
            "enable_totp.html",
            totp_uri=totp_uri,
            totp_secret=totp_secret,
            form=form  # Pass the form to the template
        )
    
    elif request.method == "POST":
        if form.validate_on_submit():
            # Verify the TOTP code
            totp_code = form.totp.data
            temp_secret = session.get('temp_totp_secret')
            
            if not temp_secret:
                flash("TOTP setup expired. Please try again.")
                return redirect(url_for('enable_totp'))
            
            totp = pyotp.TOTP(temp_secret)
            if totp.verify(totp_code):
                # Save TOTP secret to user's profile
                user_id = session.get("id")
                db.users.update_one(
                    {"_id": ObjectId(user_id)},
                    {"$set": {"totp_secret": temp_secret, "totp_enabled": True}}
                )
                
                # Clean up session
                session.pop('temp_totp_secret', None)
                flash("Two-factor authentication enabled successfully!")
                return redirect(url_for('get_recipes'))
            
            flash("Invalid TOTP code. Please try again.")
        else:
            flash("Form validation failed. Please check your input.")
        
        return redirect(url_for('enable_totp'))

@app.route("/setup_totp", methods=["GET", "POST"])
def setup_totp():
    if 'setup_totp_user_id' not in session or 'temp_totp_secret' not in session:
        return redirect(url_for('login'))
    
    form = TotpForm() 
    
    if request.method == "GET":
        user_id = session['setup_totp_user_id']
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            session.clear()
            return redirect(url_for('login'))
        
        totp_secret = session['temp_totp_secret']
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=user["email"],
            issuer_name="Recipe Manager"
        )
        
        return render_template(
            "enable_totp.html",
            totp_uri=totp_uri,
            totp_secret=totp_secret,
            form=form 
        )
    
    elif request.method == "POST":
        totp_code = request.form.get("totp")
        temp_secret = session['temp_totp_secret']
        user_id = session['setup_totp_user_id']
        
        totp = pyotp.TOTP(temp_secret)
        if totp.verify(totp_code):
            # Generate backup codes
            backup_codes = [pyotp.random_base32()[:8] for _ in range(5)]
            
            # Update user with TOTP information
            db.users.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "totp_enabled": "True",
                        "totp_secret": temp_secret,
                        "totp_backup_codes": backup_codes,
                        "totp_setup_date": datetime.utcnow(),
                        "totp_last_used": None
                    }
                }
            )
            
            # Clean up session
            session.pop('temp_totp_secret', None)
            session.pop('setup_totp_user_id', None)
            
            # Initialize regular session
            init_session(ObjectId(user_id))
            
            flash("Two-factor authentication enabled successfully! Please save your backup codes.")
            return redirect(url_for('get_recipes'))
        
        flash("Invalid verification code. Please try again.")
        return redirect(url_for('setup_totp'))

@app.route("/verify_totp", methods=["GET", "POST"])
def verify_totp():
    if 'totp_user_id' not in session:
        return redirect(url_for('login'))
    
    form = TotpForm()
    
    if form.validate_on_submit():
        user_id = session['totp_user_id']
        user = db.users.find_one({"_id": ObjectId(user_id)})
        
        if not user or user.get("totp_enabled") != "True":
            session.clear()
            return redirect(url_for('login'))
        
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(form.totp.data):
            # Update last used timestamp
            db.users.update_one(
                {"_id": ObjectId(user_id)},
                {
                    "$set": {
                        "totp_last_used": datetime.utcnow(),
                        "last_login": datetime.utcnow()
                    }
                }
            )
            
            # Clean up TOTP session data
            session.pop('totp_user_id', None)
            
            # Initialize regular session and set TOTP verification status
            init_session(ObjectId(user_id))
            session['role'] = user['role']
            session['totp_verified'] = True  
            session['totp_enabled'] = user.get('totp_enabled') 
            return redirect(url_for('get_recipes'))
        
        flash("Invalid verification code. Please try again.")
    
    return render_template("verify_totp.html", form=form)

@app.route("/disable_totp", methods=["POST"])
@login_required
def disable_totp():
    user_id = session.get("id")
    
    if not user_id:
        return redirect(url_for('login'))
    
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$unset": {"totp_secret": ""},
            "$set": {"totp_enabled": False}
        }
    )
    
    flash("Two-factor authentication has been disabled.")
    return redirect(url_for('get_recipes'))


# -----loginPage------
@app.route("/")
def home():
    if "id" in session:
        return redirect(url_for('get_recipes'))
    return render_template("index.html")


@app.route("/login", methods=("POST", "GET"))
@limiter.limit("5 per minute")
def login():
    if "id" in session and is_session_valid():
        return redirect(url_for('get_recipes'))

    form = LoginForm()
    error = ""

    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        password = form.password.data

        try:
            records = db.users
            user = records.find_one({"email": email})

            if user and bcrypt.check_password_hash(user["password"], password):
                # Check if TOTP is not yet set up
                if user.get("totp_enabled") == "False":
                    # Generate new TOTP secret
                    totp_secret = pyotp.random_base32()
                    
                    # Store the user ID and TOTP secret in session temporarily
                    session['setup_totp_user_id'] = str(user["_id"])
                    session['temp_totp_secret'] = totp_secret
                    
                    # Redirect to TOTP setup
                    return redirect(url_for('setup_totp'))
                
                # If TOTP is already enabled, verify TOTP
                if user.get("totp_enabled") == "True":
                    session['totp_user_id'] = str(user["_id"])
                    return redirect(url_for('verify_totp'))
                
                # Normal login if TOTP is not required
                db.users.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"last_login": datetime.utcnow()}}
                )
                init_session(user["_id"])
                return redirect(url_for('get_recipes'))
            else:
                error = "Invalid email or password"

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            error = "An error occurred. Please try again later."

    return render_template("login.html", form=form, error=error)
#-----signupPage------
@app.route("/signup", methods=("POST", "GET"))
def signup():
    if "id" in session:
        return redirect(url_for('get_recipes'))

    form = SignupForm()
    error = None

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.lower().strip()
        password = form.password.data
        confirm = form.conpassword.data
        role = 'user'
        # First check if passwords match
        if password != confirm:
            error = "Passwords do not match"
            return render_template("signup.html", form=form, error=error)

        # Then check password requirements
        password_errors = []
        if len(password) < 8:
            password_errors.append("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', password):
            password_errors.append("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            password_errors.append("Password must contain at least one lowercase letter")
        if not re.search(r'\d', password):
            password_errors.append("Password must contain at least one number")
        if not re.search(r'[@$!%*#?&]', password):
            password_errors.append("Password must contain at least one special character (@$!%*#?&)")

        if password_errors:
            error = " • ".join(password_errors)
            return render_template("signup.html", form=form, error=error)

        # Check if email or username already exists
        records = db.users
        if records.find_one({'email': email}):
            error = "Email already exists"
            return render_template("signup.html", form=form, error=error)
        
        if records.find_one({'username': username}):
            error = "Username already exists"
            return render_template("signup.html", form=form, error=error)

        try:
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create new user
            new_user = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
                "role":role
            }

            # Insert user into the database
            result = records.insert_one(new_user)
            session["id"] = str(result.inserted_id)
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Signup error: {str(e)}")
            error = "An error occurred during signup. Please try again."
            return render_template("signup.html", form=form, error=error)

    # If form validation failed, check if there are form errors
    if form.errors:
        # Get the first error from the form
        error = next(iter(form.errors.values()))[0]
    
    return render_template("signup.html", form=form, error=error)


# -----Homepage------
@app.route('/get_recipes')
@login_required
def get_recipes():

    user_id = session["id"]
    
    if (request.args.get('recipe_name') is not None 
        or request.args.get('preparation_time') is not None 
        or request.args.get('category_name') is not None):
        
        recipename = None
        preparationtime = None
        categoryname = None
        
        if request.args.get('recipe_name') is not None and request.args.get('recipe_name') != '':
            recipenameregex = "\W*"+request.args.get("recipe_name")+"\W*"
            recipename = re.compile(recipenameregex, re.IGNORECASE)
          
        if request.args.get('preparation_time') is not None and request.args.get('preparation_time') != '':
            preparationtimeregex = "\W*"+request.args.get("preparation_time")+"\W*"
            preparationtime = re.compile(preparationtimeregex, re.IGNORECASE)
        
        if request.args.get('category_name') is not None and request.args.get('category_name') != '':
            categoryregex = "\W*"+request.args.get("category_name")+"\W*"
            categoryname = re.compile(categoryregex, re.IGNORECASE)

        # Filter recipes by user_id and search criteria
        recipes = db.recipes.find({
            "user_id": user_id,
            "$or": [
                {"recipe_name": recipename},
                {"preparation_time": preparationtime},
                {"category_name": categoryname}
            ]
        })
        return render_template("recipes.html", recipes=recipes, categories=db.categories.find())
        
    # Filter recipes by user_id only
    recipes = db.recipes.find({"user_id": user_id})
    return render_template("recipes.html", recipes=recipes, categories=db.categories.find())


# -----Add Recipe------
@app.route('/add_recipe')
@login_required
def add_recipe():

    return render_template('addrecipe.html', categories=db.categories.find())

@app.route('/insert_recipe', methods=['POST'])
@login_required
def insert_recipe():

    try:
        recipes = db.recipes
        recipe_data = request.form.to_dict()
        recipe_data['user_id'] = session["id"]  # Add the user_id to the recipe
        recipes.insert_one(recipe_data)
        print("Recipe added successfully!")
        return redirect(url_for('get_recipes'))
    except Exception as e:
        print(f"An error occurred: {e}")
        return "An error occurred while adding the recipe.", 500

# -----Edit Recipe------
@app.route('/edit_recipe/<recipe_id>')
@login_required
def edit_recipe(recipe_id):

    
    user_id = session["id"]
    the_recipe = db.recipes.find_one({"_id": ObjectId(recipe_id), "user_id": user_id})
    
    if not the_recipe:
        return redirect(url_for('get_recipes'))  # Redirect if the recipe doesn't belong to the user
    
    all_categories = db.categories.find()
    return render_template('editrecipe.html', recipe=the_recipe, categories=all_categories)

@app.route('/update_recipe/<recipe_id>', methods=["POST"])
@login_required
def update_recipe(recipe_id):

    user_id = session["id"]
    recipes = db.recipes
    recipes.update_one(
        {'_id': ObjectId(recipe_id), "user_id": user_id},
        {
            '$set': {
                'recipe_name': request.form.get('recipe_name'),
                'category_name': request.form.get('category_name'),
                'recipe_intro': request.form.get('recipe_intro'),
                'ingredients': request.form.get('ingredients'),
                'description': request.form.get('description'),
                'preparation_time': request.form.get('preparation_time'),
                'photo_url': request.form.get('photo_url')
            }
        }
    )
    return redirect(url_for('get_recipes'))

# -----Delete Recipe------
@app.route('/delete_recipe/<recipe_id>')
@login_required
def delete_recipe(recipe_id):

    
    user_id = session["id"]
    db.recipes.delete_one({'_id': ObjectId(recipe_id), "user_id": user_id})
    return redirect(url_for('get_recipes'))

# -----Categories funcitionalities------
@app.route('/categories')
@login_required
def categories():

    return render_template('categories.html', categories=db.categories.find())

@app.route('/edit_category/<category_id>')
@login_required
def edit_category(category_id):

    return render_template('editcategory.html',
                           category=db.categories.find_one({'_id': ObjectId(category_id)}))

@app.route('/update_category/<category_id>', methods=['POST'])
@login_required
def update_category(category_id):

    db.categories.update_one(
        {'_id': ObjectId(category_id)},
        {'$set': {'category_name': request.form.get('category_name')}}
    )
    return redirect(url_for('categories'))

@app.route('/delete_category/<category_id>')
@login_required
def delete_category(category_id):

    db.categories.delete_one({'_id': ObjectId(category_id)})
    return redirect(url_for('categories'))

@app.route('/insert_category', methods=['POST'])
@login_required
def insert_category():

    category_doc = {'category_name': request.form.get('category_name')}
    db.categories.insert_one(category_doc)
    return redirect(url_for('categories'))

@app.route('/add_category')
@login_required
def add_category():

    return render_template('addcategory.html')

# -----Single Page Recipe------
@app.route('/recipe_single/<recipe_id>')
@login_required
def recipe_single(recipe_id):

    
    user_id = session["id"]
    recipe = db.recipes.find_one({'_id': ObjectId(recipe_id), "user_id": user_id})
    
    if not recipe:
        return redirect(url_for('get_recipes'))  
    
    return render_template("recipepage.html", recipe=recipe)
# ************************************************

@app.route('/manage_users')
@login_required
@totp_required
def manage_users():
    users = db.users.find()
    return render_template('manage_users.html', users=users)

@app.route('/edit_user/<user_id>')
@login_required
def edit_user(user_id):
    user = db.users.find_one({'_id': ObjectId(user_id)})
    return render_template('edit_user.html', user=user)

@app.route('/update_user/<user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {
            '$set': {
                'username': request.form.get('username'),
                'email': request.form.get('email'),
                'role': request.form.get('role')
            }
        }
    )
    flash('User updated successfully')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<user_id>')
@login_required
def delete_user(user_id):
    db.users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully')
    return redirect(url_for('manage_users'))

#**************************************
@app.route('/recovery', methods=["POST", "GET"])
def recovery():
    global code, emailSent, resetPass, emailPointed, recFinished

    if 'id' in session:
        return redirect(url_for('get_recipes'))

    form = RecoveryForm()

    # Reset the recovery process if starting fresh
    if not recFinished and form.validate_on_submit():
        emailSent = False
        code = ""
        resetPass = False
        emailPointed = ""

    # Step 1: Send recovery email
    if not emailSent and form.validate_on_submit():
        records = db.users
        email = form.email.data
        emailPointed = email
        
        # Check if user exists
        if not list(records.find({"email": email})):
            return render_template('reset.html', form=form, error="User with such records not found.")
        
        # Generate random 6-digit code
        code = random.randint(100000, 999999)
        
        # Create HTML email template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .code-container {{
                    text-align: center;
                    margin: 30px 0;
                }}
                .code {{
                    font-size: 34px;
                    background: white;
                    padding: 15px 30px;
                    border-radius: 8px;
                    color: #ff123d;
                    font-weight: bold;
                    display: inline-block;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.25);
                }}
            </style>
        </head>
        <body>
            <p>Hi,</p>
            <p>A password reset was requested for your account. Here's your recovery code:</p>
            <div class="code-container">
                <div class="code">{code}</div>
            </div>
            <p>If you didn't request this code, please ignore this email or contact support if you're concerned.</p>
            <p>Best regards,<br>Your App Team</p>
        </body>
        </html>
        """
        
        # Send the email
        email_response = sendMail(email, 'Password Recovery Code', html_content)
        
        if email_response is None:
            # Email sending failed
            return render_template('reset.html', form=form, error="Failed to send recovery email. Please try again.")
        
        emailSent = True
        return render_template('verify.html', form=VerifyForm(), code=code)

    # Step 2: Verify the code
    elif emailSent and VerifyForm().validate_on_submit():
        user_code = VerifyForm().code.data
        if int(user_code) == code:
            resetPass = True
            return render_template("resetpassword.html", form=ResetPasswordForm())
        else:
            return render_template('verify.html', form=VerifyForm(), error="Invalid code. Please try again.")

    # Step 3: Reset the password
    elif resetPass and ResetPasswordForm().validate_on_submit():
        password = ResetPasswordForm().newpassword.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        records = db.users
        print(password)
        try:
            records.update_one(
                {"email": emailPointed}, 
                {"$set": {"password": hashed_password}}
            )
            recFinished = True
            return redirect(url_for('login'))
        except Exception as e:
            return render_template("resetpassword.html", form=ResetPasswordForm(), 
                                error="Failed to update password. Please try again.")

    return render_template('reset.html', form=form)


@app.route("/destroy", methods=("POST", "GET"))
def destroy():
    if 'id' in session:
        session.pop('id')

    return redirect(url_for('login'))



@app.errorhandler(404)
def not_found_error(error):
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({'error': 'Not found'}), 404
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    app.logger.error(traceback.format_exc())
    
    if 'db' in globals():
        try:
            db.session.rollback()
        except:
            pass
            
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({'error': 'Forbidden'}), 403
    return render_template('errors/403.html'), 403

@app.errorhandler(400)
def bad_request_error(error):
    if request.headers.get('Content-Type') == 'application/json':
        return jsonify({'error': 'Bad request'}), 400
    return render_template('errors/400.html'), 400


if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT', 5000)),
            debug=False)
