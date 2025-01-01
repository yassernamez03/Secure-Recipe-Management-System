import os
import re
from flask import Flask, render_template, redirect, request, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB connection
client = MongoClient('mongodb+srv://namezyasser3:admin@cluster0.ga0p0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
db = client.recipes_manager

# -----Homepage------

@app.route('/')
@app.route('/get_recipes')
def get_recipes():
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

# -----Charts------
@app.route('/charts')
def charts():
    results = {"labels": [ ], "data": [ ]}
    categories = db.categories
    recipes = db.recipes
    all_categories = categories.find({})
    for category in all_categories:
        category_counts = recipes.find({"category_name": category["category_name"]}).count()
        results["labels"].append(category["category_name"])
        results["data"].append(category_counts)
    
    return render_template("charts.html", results=results)

# -----Add Recipe------
@app.route('/add_recipe')
def add_recipe():
    return render_template('addrecipe.html', categories=db.categories.find())

@app.route('/insert_recipe', methods=['POST'])
def insert_recipe():
    recipes = db.recipes
    recipes.insert_one(request.form.to_dict())
    return redirect(url_for('get_recipes'))

# -----Edit Recipe------
@app.route('/edit_recipe/<recipe_id>')
def edit_recipe(recipe_id):
    the_recipe = db.recipes.find_one({"_id": ObjectId(recipe_id)})
    all_categories = db.categories.find()
    return render_template('editrecipe.html', recipe=the_recipe, categories=all_categories)

@app.route('/update_recipe/<recipe_id>', methods=["POST"])
def update_recipe(recipe_id):
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
    db.recipes.delete_one({'_id': ObjectId(recipe_id)})
    return redirect(url_for('get_recipes'))

# -----Categories funcitionalities------
@app.route('/categories')
def categories():
    return render_template('categories.html', categories=db.categories.find())

@app.route('/edit_category/<category_id>')
def edit_category(category_id):
    return render_template('editcategory.html',
                           category=db.categories.find_one({'_id': ObjectId(category_id)}))

@app.route('/update_category/<category_id>', methods=['POST'])
def update_category(category_id):
    db.categories.update_one(
        {'_id': ObjectId(category_id)},
        {'$set': {'category_name': request.form.get('category_name')}}
    )
    return redirect(url_for('categories'))

@app.route('/delete_category/<category_id>')
def delete_category(category_id):
    db.categories.delete_one({'_id': ObjectId(category_id)})
    return redirect(url_for('categories'))

@app.route('/insert_category', methods=['POST'])
def insert_category():
    category_doc = {'category_name': request.form.get('category_name')}
    db.categories.insert_one(category_doc)
    return redirect(url_for('categories'))

@app.route('/add_category')
def add_category():
    return render_template('addcategory.html')

# -----Single Page Recipe------
@app.route('/recipe_single/<recipe_id>')
def recipe_single(recipe_id):
    return render_template("recipepage.html",
                           recipes=db.recipes.find({'_id': ObjectId(recipe_id)}))

# ************************************************

if __name__ == '__main__':
    app.run(host=os.environ.get('IP'),
            port=int(os.environ.get('PORT', 5000)),
            debug=True)
