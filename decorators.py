import os
import jwt
from flask import jsonify, request
from functools import wraps
from models import AdminUsers, BlacklistToken


def check_blacklist(auth_token):
    # check whether auth token has been blacklisted
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
            return jsonify({'message' : 'Token is missing !!'}), 401

        try:
            is_blacklisted_token = check_blacklist(token)
            if is_blacklisted_token:
                return 'Token expired. Please log in again.'
            else:
                # decoding the payload to fetch the stored details
                data = jwt.decode(token, os.environ['TOKEN'])
                current_user = AdminUsers.query\
                    .filter_by(id=data['public_id'])\
                    .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return f(request, current_user, *args, **kwargs)

    return decorated
