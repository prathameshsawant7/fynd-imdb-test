import os
import json
# imports for PyJWT authentication
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta



app = Flask(__name__)
app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ma = Marshmallow(app)
token = os.environ['TOKEN']



token = os.environ['TOKEN']

from models import Movies, AdminUsers, BlacklistToken
from decorators import token_required

import uuid
@app.route('/get_token/')
def get_token():
    return {"token": token}

@app.route('/api/admin_users/', methods = ['POST'])
def admin_users():
    email = request.json.get('email')
    password = request.json.get('password')
    if email is None or password is None:
        return {"error_message": "Please enter valid email and password"}, 400
    if AdminUsers.query.filter_by(email=email).first() is not None:
        return {"error_message": "User already exist"}, 400
    user = AdminUsers(email=email, password=password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "New Admin user created successfully."}), 201


# User Database Route
# this route sends back list of users users
@app.route('/user/', methods =['GET'])
@token_required
def get_all_users(request, user):
    # querying the database
    # for all the entries in it
    users = AdminUsers.query.all()
    # converting the query objects
    # to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'email': user.email
        })

    return jsonify({'users': output})



# route for loging user in
@app.route('/login', methods =['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    user = AdminUsers.query\
        .filter_by(email=auth.get('email'))\
        .first()

    if not user:
        # returns 401 if user does not exist
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': str(user.id),
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, os.environ['TOKEN'])

        return make_response(jsonify({'token': token.decode('UTF-8')}), 200)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
    )

# signup route
@app.route('/signup/', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    user = AdminUsers.query\
        .filter_by(email=email)\
        .first()
    if not user:
        # database ORM object
        user = AdminUsers(
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)


# logout route
@app.route('/logout/', methods =['POST'])
@token_required
def logout(request,user):
    print(request.headers)
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
        # mark the token as blacklisted
    blacklist_token = BlacklistToken(token=token)
    try:
        # insert the token
        db.session.add(blacklist_token)
        db.session.commit()
        response_object = {
            'status': 'success',
            'message': 'Successfully logged out.'
        }
        return make_response(jsonify(response_object)), 200
    except Exception as e:
        response_object = {
            'status': 'fail',
            'message': str(e)
        }
        return make_response(jsonify(response_object)), 200


import json
from datetime import datetime


# parse movie list route
@app.route('/upload_movies/', methods=['POST'])
@token_required
def upload_movie(request, user):
    # creates a dictionary of the form data
    file = request.files['file']
    myfile = file.read()
    movies = json.loads(myfile)
    entries = []
    for movie_data in movies:
        name = movie_data['name']
        director = movie_data['director']
        popularity = movie_data['99popularity']
        genre = ','.join(movie_data['genre'])
        imdb_score = movie_data['imdb_score']
        if not db.session.query(Movies).filter_by(name=name, director=director).first():
            movie = Movies(
                name=name,
                director=director,
                popularity=popularity,
                genre=genre,
                imdb_score=imdb_score,
                created_by=user.id,
            )
            entries.append(movie)

    if entries:
        #insert_command = Movies.__table__.insert().prefix_with('OR REPLACE').values(entries)
        db.session.add_all(entries)
        #db.session.execute(insert_command)
        db.session.commit()

    response_object = {
        'status': 'success',
        'message': 'File Uploaded Successfully.'
    }
    return make_response(jsonify(response_object)), 201


# Add movie list route
@app.route('/add_movie/', methods=['POST'])
@token_required
def add_movie(request,user):
    movie_data = json.loads(request.data)
    name = movie_data['name']
    director = movie_data['director']
    popularity = movie_data['99popularity']
    genre = ','.join(movie_data['genre'])
    imdb_score = movie_data['imdb_score']
    if not db.session.query(Movies).filter_by(name=name, director=director).first():
        movie = Movies(
            name=name,
            director=director,
            popularity=popularity,
            genre=genre,
            imdb_score=imdb_score,
            created_by=user.id,
        )
        db.session.add(movie)
        db.session.commit()
        response_object = {
            'status': 'success',
            'message': 'Movie added successfully.',
            'data': movie.serialize()
        }
        return make_response(jsonify(response_object)), 201
    else:
        response_object = {
            'status': 'error',
            'message': 'Movie already exists.'
        }
        return make_response(jsonify(response_object)), 201


@app.route('/update_movie/<id>', methods=['PATCH'])
@token_required
def update_movie(request,user,id):
    movie = Movies.query.get(id)
    movie_data = json.loads(request.data)

    if "99popularity" in movie_data:
        movie.popularity = movie_data['99popularity']
        del movie_data['99popularity']

    for key, val in movie_data.items():
        setattr(movie, key, val)

    movie.updated_by = user.id
    movie.updated_at = datetime.now()
    db.session.commit()
    response_object = {
        'status': 'success',
        'message': 'Movie updated successfully.',
        'data': movie.serialize()
    }
    return make_response(jsonify(response_object)), 200


@app.route('/delete_movie/<id>', methods=['DELETE'])
@token_required
def delete_movie(request, user, id):
    movie = Movies.query.get(id)
    db.session.delete(movie)
    db.session.commit()
    response_object = {
        'status': 'success',
        'message': 'Movie deleted successfully.'
    }
    return make_response(jsonify(response_object)), 200


@app.route('/movie/<id>', methods=['GET'])
def movie_details(id):
    movie = Movies.query.get(id)
    response_object = {
        'status': 'success',
        'data': movie.serialize()
    }
    return make_response(jsonify(response_object)), 200


@app.route('/api/admin_login/', methods=['POST'])
def admin_login():
    email = request.json.get('email')
    password = request.json.get('password')
    # first try to authenticate by token

    try:
        user = db.session.query(AdminUsers).filter_by(email=email, password=password).one()
        token = user.generate_auth_token()
        return jsonify({"token": str(token)}), 200
    except:
        return jsonify({"error_message": "Invalid Email or Password"}), 200


    # user = AdminUsers.verify_auth_token(email_or_token)
    # if not user:
    #     # try to authenticate with username/password
    #     user = User.query.filter_by(username=username_or_token).first()
    #     if not user or not user.verify_password(password):
    #         return False


# @app.route('/api/token')
# @auth.login_required
# def get_auth_token():
#     token = g.user.generate_auth_token()
#     return jsonify({ 'token': token.decode('ascii') })
#
#

# from flask_httpauth import HTTPBasicAuth
# auth = HTTPBasicAuth()
#
# @app.route('/api/resource')
# @auth.login_required
# def get_resource():
#     return jsonify({ 'data': 'Hello, %s!' % g.user.username })

# @app.route('/get_token/')
# def get_token():
#     return {"token": token}


#
# from models import WebhookData
#
# @app.route('/get_token/')
# def get_token():
#     return {"token": token}
#
#
# @app.route('/webhook_url/', methods=['POST'])
# def webhook():
#     if request.headers.get('Token', None) == token:
#         try:
#             system = request.args.get('system')
#             data = request.get_data(as_text=True)
#             webhook_data = WebhookData(
#                 system=system,
#                 data=json.loads(data)
#             )
#             db.session.add(webhook_data)
#             db.session.commit()
#             return make_response(f"Webhook data created successfully")
#         except Exception as e:
#             return {"error": str(e)}, 400
#     else:
#         return {"error": "Invalid Token"}, 401
#
#
# @app.route('/get_data/', methods=['GET'])
# def getData():
#     if request.headers.get('Token', None) == token:
#         try:
#             system = request.args.get('system')
#             record = db.session.query(WebhookData).filter_by(system=system).order_by(WebhookData.id.desc()).first()
#             result = {
#                 "system": record.system,
#                 "data": json.loads(record.data),
#                 "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S")
#             }
#             return make_response(result)
#         except Exception as e:
#             return {"error": str(e)},400
#     else:
#         return {"error": "Invalid Token"},401



if __name__ == '__main__':
    app.run()
