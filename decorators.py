import os
import jwt
from flask import request, jsonify, make_response
from functools import wraps
from models import AdminUsers, BlacklistToken


def check_blacklist(auth_token):
    """
    Verify token is in blacklist or not
    :param auth_token: x-access-token
    :return: Boolean
    """
    res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
    if res:
        return True
    else:
        return False


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
            response_object = {
                'status': 'error',
                'message': 'Token is missing.'
            }
            return make_response(jsonify(response_object)), 401

        try:
            is_blacklisted_token = check_blacklist(token)
            if is_blacklisted_token:
                response_object = {
                    'status': 'error',
                    'message': 'Token expired. Please login again.'
                }
                return make_response(jsonify(response_object)), 401
            else:
                # decoding the payload to fetch the stored details
                data = jwt.decode(token, os.environ['TOKEN'])
                current_user = AdminUsers.query\
                    .filter_by(id=data['public_id'])\
                    .first()
        except:
            response_object = {
                'status': 'error',
                'message': 'Token is invalid.'
            }
            return make_response(jsonify(response_object)), 401
        # returns the current logged in users contex to the routes
        return f(request, current_user, *args, **kwargs)

    return decorated
