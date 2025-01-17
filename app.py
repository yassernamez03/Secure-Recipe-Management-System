import os
import re
from flask import Flask, session , render_template, redirect, request, url_for , jsonify
from werkzeug.security import check_password_hash, generate_password_hash

from form import *
import random
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
secret_key = os.urandom(12).hex()
app.config['SECRET_KEY'] = secret_key
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

bcrypt = Bcrypt(app)


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

def init_session(user_id):
    """Initialize secure session with proper timeout"""
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)
    session["id"] = str(user_id)
    session["login_time"] = datetime.utcnow().timestamp()

def is_session_valid():
    """Check if current session is valid"""
    if "login_time" not in session:
        return False
    login_time = datetime.fromtimestamp(session["login_time"])
    return datetime.utcnow() - login_time < app.permanent_session_lifetime

@app.before_request
def before_request():
    """Verify session validity before each request"""
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

# -----loginPage------
@app.route("/")
def home():
    if "id" in session:
        return redirect(url_for('get_recipes'))
        
    return render_template("index.html")


@app.route("/login", methods=("POST", "GET"))
@limiter.limit("5 per minute")  # Rate limiting for brute force protection
def login():
    if "id" in session and is_session_valid():
        return redirect(url_for('get_recipes'))

    form = LoginForm()
    error = ""

    if form.validate_on_submit():
        email = form.email.data.lower().strip()  # Normalize email
        password = form.password.data

        try:
            records = db.users
            user = records.find_one({"email": email})

            if user and bcrypt.check_password_hash(user["password"], password):
                db.login_attempts.insert_one({
                    "user_id": user["_id"],
                    "timestamp": datetime.utcnow(),
                    "success": True,
                    "ip": request.remote_addr
                })
                init_session(user["_id"])
                return redirect(url_for('get_recipes'))
            else:
                
                db.login_attempts.insert_one({
                    "email": email,
                    "timestamp": datetime.utcnow(),
                    "success": False,
                    "ip": request.remote_addr
                })
                error = "Invalid email or password"  # Generic error message

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
    errors = []

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.lower().strip()
        password = form.password.data
        confirm = form.conpassword.data

        # Check all password requirements
        requirements = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'number': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[@$!%*#?&]', password))
        }

        if not all(requirements.values()):
            if not requirements['length']:
                errors.append("Password must be at least 12 characters long")
            if not requirements['uppercase']:
                errors.append("Password must contain at least one uppercase letter")
            if not requirements['lowercase']:
                errors.append("Password must contain at least one lowercase letter")
            if not requirements['number']:
                errors.append("Password must contain at least one number")
            if not requirements['special']:
                errors.append("Password must contain at least one special character (@$!%*#?&)")

        if password != confirm:
            errors.append("Passwords do not match")

        if not errors:
            records = db.users
            if records.find_one({'email': email}):
                errors.append("Email already exists")
            elif records.find_one({'username': username}):
                errors.append("Username already exists")
            else:
                # Hash the password
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                # Create new user
                new_user = {
                    "username": username,
                    "email": email,
                    "password": hashed_password,
                    "created_at": datetime.utcnow(),
                    "last_login": datetime.utcnow()
                }

                # Insert user into the database
                result = records.insert_one(new_user)
                session["id"] = str(result.inserted_id)
                return redirect(url_for('login'))

    return render_template("signup.html", form=form, errors=errors)


# -----Homepage------

@app.route('/get_recipes')
def get_recipes():
    if "id" not in session:
        return redirect(url_for('login'))
    
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

        # Accessing the 'recipes' collection and querying the database
        recipes = db.recipes.find({ "$or": [{"recipe_name": recipename}, {"preparation_time": preparationtime}, {"category_name": categoryname}] })
        return render_template("recipes.html", recipes=recipes, categories=db.categories.find())
        
    return render_template("recipes.html", recipes=db.recipes.find(), categories=db.categories.find())


# -----Add Recipe------
@app.route('/add_recipe')
def add_recipe():
    if "id" not in session:
        return redirect(url_for('login'))
    return render_template('addrecipe.html', categories=db.categories.find())

@app.route('/insert_recipe', methods=['POST'])
def insert_recipe():
    try:
        recipes = db.recipes
        recipes.insert_one(request.form.to_dict())
        print("Recipe added successfully!")
        print(request.form.to_dict())
        return redirect(url_for('get_recipes'))
    except Exception as e:
        print(f"An error occurred: {e}")
        return "An error occurred while adding the recipe.", 500

# -----Edit Recipe------
@app.route('/edit_recipe/<recipe_id>')
def edit_recipe(recipe_id):
    if "id" not in session:
        return redirect(url_for('login'))
    the_recipe = db.recipes.find_one({"_id": ObjectId(recipe_id)})
    all_categories = db.categories.find()
    return render_template('editrecipe.html', recipe=the_recipe, categories=all_categories)

@app.route('/update_recipe/<recipe_id>', methods=["POST"])
def update_recipe(recipe_id):
    if "id" not in session:
        return redirect(url_for('login'))
    recipes = db.recipes
    recipes.update_one({'_id': ObjectId(recipe_id)},
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
    })
    return redirect(url_for('get_recipes'))

# -----Delete Recipe------
@app.route('/delete_recipe/<recipe_id>')
def delete_recipe(recipe_id):
    if "id" not in session:
        return redirect(url_for('login'))
    db.recipes.delete_one({'_id': ObjectId(recipe_id)})
    return redirect(url_for('get_recipes'))

# -----Categories funcitionalities------
@app.route('/categories')
def categories():
    if "id" not in session:
        return redirect(url_for('login'))
    return render_template('categories.html', categories=db.categories.find())

@app.route('/edit_category/<category_id>')
def edit_category(category_id):
    if "id" not in session:
        return redirect(url_for('login'))
    return render_template('editcategory.html',
                           category=db.categories.find_one({'_id': ObjectId(category_id)}))

@app.route('/update_category/<category_id>', methods=['POST'])
def update_category(category_id):
    if "id" not in session:
        return redirect(url_for('login'))
    db.categories.update_one(
        {'_id': ObjectId(category_id)},
        {'$set': {'category_name': request.form.get('category_name')}}
    )
    return redirect(url_for('categories'))

@app.route('/delete_category/<category_id>')
def delete_category(category_id):
    if "id" not in session:
        return redirect(url_for('login'))
    db.categories.delete_one({'_id': ObjectId(category_id)})
    return redirect(url_for('categories'))

@app.route('/insert_category', methods=['POST'])
def insert_category():
    if "id" not in session:
        return redirect(url_for('login'))
    category_doc = {'category_name': request.form.get('category_name')}
    db.categories.insert_one(category_doc)
    return redirect(url_for('categories'))

@app.route('/add_category')
def add_category():
    if "id" not in session:
        return redirect(url_for('login'))
    return render_template('addcategory.html')

# -----Single Page Recipe------
@app.route('/recipe_single/<recipe_id>')
def recipe_single(recipe_id):
    if "id" not in session:
        return redirect(url_for('login'))
    return render_template("recipepage.html",
                           recipes=db.recipes.find({'_id': ObjectId(recipe_id)}))

# ************************************************

@app.route('/recovery', methods=("POST", "GET"))
def recovery():
    global code
    global emailSent
    global resetPass
    global emailPointed
    global recFinished

    if 'id' in session:
        return render_template(url_for('get_recipes'))

    form = RecoveryForm()

    if not(recFinished) and form.validate_on_submit():
        emailSent = False
        code = ""
        resetPass = False
        emailPointed = ""

    if not(emailSent) and form.validate_on_submit():
        records = db.users
        email = form.email.data
        emailPointed = email
        if not(len(list(records.find({"email":email})))):
            return render_template('reset.html', form=form, error="User with such records not found.")
        #Generating random 6-digit-code
        code = random.randint(100000, 999999)
        htmlcode = """<link rel="preconnect" href="https://fonts.googleapis.com">
                    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
                    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@100;400&display=swap" rel="stylesheet"> 
                    <body>
                    <style>
                    * {
                            font-family: 'Roboto';
                        }
                    </style>
                    <p>Hi, this email contains a recovery code that you can use to change the password of your account. Here's the <strong>Recovery Code</strong>: </p>
                    <center>
                    <p style="font-size:34px;background: white; width: fit-content; padding: .75em 1em; border-radius: 6px; color: #ff123d; font-weight: bold; box-shadow: rgb(0, 0, 0, .25) 0 2px 5px;">"""+str(code)+"""</p>
                    </center>
                    </body>"""
        sendMail(email, 'Account Recovery', htmlcode)
        emailSent = True
        return render_template('verify.html' , form=VerifyForm(), code=code)
    elif emailSent and VerifyForm().validate_on_submit():
        userCode = VerifyForm().code.data
        if(int(userCode)==code):
            resetPass = True
            return render_template("resetpassword.html", form=ResetPasswordForm())
    elif resetPass and ResetPasswordForm().validate_on_submit():
        password = ResetPasswordForm().newpassword.data
        records = db.users
        myquery = { "email": emailPointed }
        newvalues = { "$set": { "password":generate_password_hash(password)  } }
        records.update_one(myquery, newvalues)

        recFinished = True

        return redirect(url_for('login'))

    return render_template('reset.html', form=form)


@app.route("/destroy", methods=("POST", "GET"))
def destroy():
    if 'id' in session:
        session.pop('id')

    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT', 5000)),
            debug=True)
