import os
import json
import jwt
import logging
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
if 'DYNO' in os.environ:
    app.logger.addHandler(logging.StreamHandler(sys.stdout))
    app.logger.setLevel(logging.ERROR)
else:
    logging.basicConfig(filename='imdb.log', level=logging.INFO)

app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from datetime import datetime, timedelta
from elasticsearch_operations import ESOperations
from models import Movies, AdminUsers, BlacklistToken
from decorators import token_required
from validate_fields import validate_email, validate_password

logging.info('Logging Started')

@app.route('/api/v1/login', methods=['POST'])
def login():
    """
    Admin User Login
    :param FORMDATA[email]: Admin User Email ID
    :param FORMDATA[password]: Admin User Password
    :return: Token for CRUD Operations on Movies
    """
    # Get Form Data [Email,Password]
    auth = request.form
    if not auth or not auth.get('email') or not auth.get('password'):
        # Email/Password is missing
        response_object = {
            'status': 'error',
            'message': 'Email and Password are required.'
        }
        return make_response(jsonify(response_object)), 401

    # Check if Email is registered or not.
    user = AdminUsers.query\
        .filter_by(email=auth.get('email'))\
        .first()

    if not user:
        # If Email is not registered
        response_object = {
            'status': 'error',
            'message': 'Email is not registered.'
        }
        return make_response(jsonify(response_object)), 401

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': str(user.id),
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, os.environ['TOKEN'])
        return make_response(jsonify({'token': token.decode('UTF-8')}), 200)
    # If Password is wrong
    response_object = {
        'status': 'error',
        'message': 'Password is incorrect.'
    }
    return make_response(jsonify(response_object)), 403


@app.route('/api/v1/signup/', methods=['POST'])
def signup():
    """
    :param FORMDATA['name']: Name of Admin User
    :param FORMDATA['email']: Email ID of Admin User
    :param FORMDATA['password']: Password of Admin User
    :return:
    """
    data = request.form
    name, email, password = data.get('name', None), data.get('email', None), data.get('password', None)

    # Validate Email
    if not validate_email(email):
        # Invalid Email
        response_object = {
            'status': 'error',
            'message': 'Invalid Email ID.'
        }
        return make_response(jsonify(response_object)), 403

    logging.info('Email validated successfully')

    # Validate Password
    msg = validate_password(password)
    if msg != "success":
        # Invalid Password
        response_object = {
            'status': 'error',
            'message': msg
        }
        return make_response(jsonify(response_object)), 403

    logging.info('Password validated successfully')

    if not name:
        # Invalid Name
        response_object = {
            'status': 'error',
            'message': 'Please enter name.'
        }
        return make_response(jsonify(response_object)), 403

    logging.info('Name validated successfully')

    # Check if it is a existing user
    user = AdminUsers.query\
        .filter_by(email=email)\
        .first()

    if not user:
        user = AdminUsers(
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # Create Admin User
        db.session.add(user)
        db.session.commit()

        response_object = {
            'status': 'success',
            'message': 'Admin user registered successfully.'
        }
        return make_response(jsonify(response_object)), 201
    else:
        response_object = {
            'status': 'error',
            'message': 'User already exists.'
        }
        return make_response(jsonify(response_object)), 202


@app.route('/api/v1/logout/', methods =['POST'])
@token_required
def logout(request, user):
    """
    Logout Admin User Token
    :param request: API Request Details
    :param user: Admin User Details
    """
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
        # Mark the token as blacklisted
        blacklist_token = BlacklistToken(token=token)
        try:
            db.session.add(blacklist_token)
            db.session.commit()
            response_object = {
                'status': 'success',
                'message': 'Successfully logged out.'
            }
            return make_response(jsonify(response_object)), 200
        except Exception as e:
            logging.info(str(e))
            response_object = {
                'status': 'fail',
                'message': str(e)
            }
            return make_response(jsonify(response_object)), 200
    else:
        response_object = {
            'status': 'fail',
            'message': "Invalid Token"
        }
        return make_response(jsonify(response_object)), 400


@app.route('/api/v1/add_movie/', methods=['POST'])
@token_required
def add_movie(request, user):
    """
    Add new Movie
    :param request: API Request Details
    :param user: Admin User Details
    """
    try:
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

            logging.info("Movie added to DB successfully")

            # Add Movie to Elasticsearch
            try:
                movie_data['id'] = str(movie.id)
                es = ESOperations("imdb")
                es.create_document(movie_data)
                logging.info("Movie added to ES successfully")
            except Exception as e:
                logging.error(str(e))
                pass

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
    except Exception as e:
        logging.error(str(e))
        response_object = {
            'status': 'error',
            'message': str(e)
        }
        return make_response(jsonify(response_object)), 400


@app.route('/api/v1/update_movie/<id>', methods=['PATCH'])
@token_required
def update_movie(request, user, id):
    """
    Update Movie by Movie ID
    :param request: API Request Details
    :param user: Admin User Details
    :param id: Movie ID to Update Movie
    """
    try:
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

        logging.info("Movie updated to DB successfully")

        movie_data = {
            "id": str(movie.id),
            "name": movie.name,
            "director": movie.director,
            "99popularity": movie.popularity,
            "genre": movie.genre.split(","),
            "imdb_score": movie.imdb_score
        }

        # Update Movie in Elasticsearch
        try:
            es = ESOperations("imdb")
            es.update_document(movie_data)
            logging.info("Movie updated to ES successfully")
        except Exception as e:
            logging.error(str(e))
            pass

        response_object = {
            'status': 'success',
            'message': 'Movie updated successfully.',
            'data': movie.serialize()
        }
        return make_response(jsonify(response_object)), 200
    except Exception as e:
        logging.error(str(e))
        response_object = {
            'status': 'error',
            'message': 'Movie does not exists.'
        }
        return make_response(jsonify(response_object)), 400


@app.route('/delete_movie/<id>', methods=['DELETE'])
@token_required
def delete_movie(request, user, id):
    """
    Delete Movie by Movie ID
    :param request: API Request Details
    :param user: Admin User Details
    :param id: Movie ID to Delete Movie
    """
    try:
        movie = Movies.query.get(id)
        db.session.delete(movie)
        db.session.commit()

        # Delete Movie from Elasticsearch
        try:
            movie_data = {"id": id}
            es = ESOperations("imdb")
            es.delete_document(movie_data)
        except Exception as e:
            logging.error(str(e))
            pass

        response_object = {
            'status': 'success',
            'message': 'Movie deleted successfully.'
        }
        return make_response(jsonify(response_object)), 200
    except Exception as e:
        logging.error(str(e))
        response_object = {
            'status': 'error',
            'message': 'Movie does not exists.'
        }
        return make_response(jsonify(response_object)), 400


@app.route('/api/v1/movie/<id>', methods=['GET'])
def movie_details(id):
    """
    Get Full Movie Details
    :param id: Movie ID
    :return: Movie Details
    """
    try:
        movie = Movies.query.get(id)
        movie.views = int(movie.views) + 1
        db.session.commit()
        response_object = {
            'status': 'success',
            'data': movie.serialize()
        }
        return make_response(jsonify(response_object)), 200
    except Exception as e:
        logging.error(str(e))
        response_object = {
            'status': 'error',
            'message': 'Movie does not exists.'
        }
        return make_response(jsonify(response_object)), 400


@app.route('/api/v1/search/', methods=['GET'])
def movie_search():
    """
    Search Movies on basis of Keyword else return all movies
    :param [optional]: To Search documents
    :return: List of Movies
    """
    filters = {}
    keyword = request.args.get('keyword', None)

    es = ESOperations("imdb")
    res = es.search_document(keyword, filters)
    response_object = {
        'status': 'success',
        'data': res['hits']['hits']
    }
    return make_response(jsonify(response_object)), 200


@app.route('/api/v1/upload_movies/', methods=['POST'])
@token_required
def upload_movie(request, user):
    """
    Bulk Upload Movies List
    :param request: API Request Details
    :param user: Admin User Details
    """
    file = request.files['file']
    myfile = file.read()
    movies = json.loads(myfile)
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
            db.session.add(movie)
            db.session.commit()

            # Add Movies Data to Elasticsearch
            movie_data['id'] = str(movie.id)
            es = ESOperations("imdb")
            es.create_document(movie_data)

    response_object = {
        'status': 'success',
        'message': 'File Uploaded Successfully.'
    }
    return make_response(jsonify(response_object)), 201

if __name__ == '__main__':
    app.run()
