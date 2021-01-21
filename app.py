from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, asc, func
from flask_marshmallow import Marshmallow
# imports for PyJWT authentication
from functools import wraps
import jwt
from datetime import datetime, timedelta
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
from pyhunter import PyHunter
import clearbit
from statistics import mean

app = Flask(__name__)

app.config['SECRET_KEY'] = 'recepte'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recepte.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    recipes = db.relationship('Recipe', backref='author', lazy=True)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    recipe_text = db.Column(db.String(250), nullable=False)
    rating = db.Column(db.String(250))
    average_rating = db.Column(db.Numeric(1,2))
    inredients = db.relationship('Ingredient', secondary='recipe_ingredient', backref=db.backref('contains_inredient', lazy = 'dynamic'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

db.Table('recipe_ingredient',
    db.Column('recipe_id', db.Integer, db.ForeignKey('recipe.id')),
    db.Column('ingredient_id', db.Integer, db.ForeignKey('ingredient.id'))
)


class IngredientSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Ingredient

class RecipeSchema(ma.SQLAlchemyAutoSchema):
    inredients = ma.Nested(IngredientSchema, many=True)
    class Meta:
        model = Recipe


db.create_all()
db.session.commit()


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query \
                .filter_by(public_id=data['public_id']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


#User registration
@app.route('/registration', methods=['GET', 'POST'])
def registration():

    email = request.form['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    password = request.form['password']

    #checking for existing user
    user = User.query.filter_by(email=email).first()
    if user:
        return {'success': False,
                'msg': 'User already exists! Please Log in!'}

    try:
        #HUNTER


        hunter = PyHunter('8a225ea7e524328c62224526b273d48266a41d65')
        hunter.email_verifier(email)
        #CLEARBIT
        clearbit.key = 'sk_9910ef6078230afe0cf6460e59da8bf4'
        user = clearbit.Person.find(email=email, stream=True)
        '''if user != None:
            user['some_parametar_for_get_data']'''

        new_user = User(public_id=str(uuid.uuid4()),
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return {'success': True,
                'msg': 'Successfully registered!'}
    except:
        return {'success': False,
                'msg': 'Registration failed, please try again!'}

#User login
@app.route('/login', methods=['GET', 'POST'])
def login():

    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()
    if not user:
        return {'success': False,
                'msg': 'Could not verify!'}

    if check_password_hash(user.password, password):
        token = jwt.encode({
            'public_id': user.public_id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return {'token': token.decode('UTF-8')}

    return {'success': False,
            'msg': 'Could not verify! Wrong Password!'}


@app.route('/create_recipe', methods=['GET', 'POST'])
@token_required
def create_recipe(current_user):

    name = request.form['name']
    recipe_text = request.form['recipe_text']
    inredients = request.form['inredients']

    new_recipe = Recipe(name=name,
                        recipe_text=recipe_text,
                        author_id=current_user.id)
    db.session.add(new_recipe)
    db.session.commit()

    inredients_list = [x.strip() for x in inredients.split(',')]
    for i in inredients_list:
        inredient = Ingredient.query.filter_by(name=i).first()

        if inredient is not None:
            inredient.contains_inredient.append(new_recipe)
            db.session.commit()
        else:
            new_inredient = Ingredient(name=i)
            db.session.add(new_inredient)
            db.session.commit()
            new_inredient.contains_inredient.append(new_recipe)
            db.session.commit()

    return {'success': True,
                'msg': 'Recipe created!'}


@app.route('/rating_recipe', methods=['GET', 'POST'])
@token_required
def rating_recipe(current_user):

    id = request.form['id']
    rating_number = request.form['rating_nubmer']

    recipe = Recipe.query.filter_by(id=id).first()

    if current_user.id == recipe.author_id:
        return {'success': False,
                'msg': 'You cannot rate own recipes!'}

    if int(rating_number) < 1 or int(rating_number) > 5:
        return {'success': False,
                'msg': 'Rating must be number between 1 and 5!'}

    rating = recipe.rating
    if rating is None:
        rating = []
    else:
        rating = rating.split(',')

    rating.append(rating_number)

    #calculate new average value
    rating = [int(i) for i in rating]
    average_value = mean(rating)
    recipe.average_rating = average_value

    rating_str = ','.join(str(r) for r in rating)
    recipe.rating = rating_str
    db.session.commit()

    return {'success': True,
            'msg': 'Successfully rated!'}


@app.route('/allrecipes', methods=['GET'])
@token_required
def all_recipe(current_user):
    recipes = Recipe.query.all()

    recipe_schema = RecipeSchema(many=True)
    output = recipe_schema.dump(recipes)

    return jsonify({'recipes': output})


@app.route('/ownrecipes', methods=['GET'])
@token_required
def own_recipe(current_user):
    recipes = Recipe.query.filter_by(author_id=current_user.id).all()

    recipe_schema = RecipeSchema(many=True)
    output = recipe_schema.dump(recipes)

    return jsonify({'recipes': output})


@app.route('/ingredients_top5', methods=['GET'])
@token_required
def ing_top5(current_user):
    top5 = db.session.query(Ingredient)\
        .outerjoin(Ingredient, Recipe.inredients)\
        .group_by(Ingredient.id)\
        .order_by(desc(db.func.count(Recipe.id)))\
        .limit(5)\
        .all()

    ingredient_schema = IngredientSchema(many=True)
    output = ingredient_schema.dump(top5)

    return jsonify({'ingredients': output})


@app.route('/search', methods=['GET', 'POST'])
@token_required
def search(current_user):
    name = request.form.get('name')
    text = request.form.get('text')
    ingredients = request.form.get('ingredients')

    if name:

        recipe = (
            db.session.query(Recipe)
                .filter(Recipe.name.ilike('%' + name + '%'))
                .order_by(Recipe.name)
                .all()
        )

        recipe_schema = RecipeSchema(many=True)
        output = recipe_schema.dump(recipe)

        if len(output) > 0:
            return jsonify({'recipe': output})
        else:
            return jsonify({'recipe': 'Recipe not found!'})

    if text:

        recipe = (
            db.session.query(Recipe)
                .filter(Recipe.recipe_text.ilike('%' + text + '%'))
                .order_by(Recipe.name)
                .all()
        )

        recipe_schema = RecipeSchema(many=True)
        output = recipe_schema.dump(recipe)

        if len(output) > 0:
            return jsonify({'recipe': output})
        else:
            return jsonify({'recipe': 'Recipe not found!'})

    if ingredients:

        recipe = (
            db.session.query(Recipe)
                .outerjoin(Ingredient, Recipe.inredients)
                .filter(Ingredient.name.ilike('%' + ingredients + '%'))
                .order_by(Recipe.name)
                .all()
        )

        recipe_schema = RecipeSchema(many=True)
        output = recipe_schema.dump(recipe)
        print(len(output))
        if len(output) > 0:
            return jsonify({'recipe': output})
        else:
            return jsonify({'recipe': 'Recipe not found!'})


@app.route('/min_ingredients', methods=['GET'])
@token_required
def min(current_user):
    min = db.session.query(Recipe)\
        .outerjoin(Ingredient, Recipe.inredients) \
        .group_by(Recipe.id) \
        .order_by(asc(db.func.count(Ingredient.id)))\
        .limit(5)\
        .all()

    recipe_schema = RecipeSchema(many=True)
    output = recipe_schema.dump(min)

    return jsonify({'recipe': output})


@app.route('/max_ingredients', methods=['GET'])
@token_required
def max(current_user):
    #db.func.count(Ingredient.id)
    max = db.session.query(Recipe)\
        .outerjoin(Ingredient, Recipe.inredients) \
        .group_by(Recipe.id) \
        .order_by(desc(db.func.count(Ingredient.id)))\
        .limit(5)\
        .all()

    recipe_schema = RecipeSchema(many=True)
    output = recipe_schema.dump(max)

    return jsonify({'recipe': output})

if __name__ == "__main__":
    app.run(debug = True)