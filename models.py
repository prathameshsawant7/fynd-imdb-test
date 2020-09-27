import uuid
from sqlalchemy.orm import *
from app import db
from sqlalchemy import types
from sqlalchemy.dialects.mysql import FLOAT
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class GUID(types.TypeDecorator):
    """Platform-independent GUID type.

    Uses Postgresql's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.

    """
    impl = types.String(32)

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                value = uuid.UUID(value)
            return value


class AdminUsers(db.Model):
    __tablename__ = 'admin_users'

    id = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False, index=True)
    password = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


class Movies(db.Model):
    __tablename__ = 'movies'

    id = db.Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(80), nullable=False, index=True)
    director = db.Column(db.String(80), nullable=False, index=True)
    popularity = db.Column(FLOAT(precision=10, scale=1))
    genre = db.Column(db.Text, nullable=False, default="")
    imdb_score = db.Column(FLOAT(precision=10, scale=1))
    views = db.Column(db.Integer, default=0)
    created_by = db.Column(GUID(), db.ForeignKey('admin_users.id'))
    updated_by = db.Column(GUID(), db.ForeignKey('admin_users.id'))
    created_at = db.Column(db.DateTime, default=datetime.now())
    updated_at = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, name, director, popularity, genre, imdb_score, created_by, views=0, updated_by=None):
        self.name = name
        self.director = director
        self.popularity = popularity
        self.genre = genre
        self.imdb_score = imdb_score
        self.views = views
        self.created_by = created_by
        self.updated_by = updated_by

    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': str(self.id),
            'name': self.name,
            'director': self.director,
            '99popularity':self.popularity,
            'genre': self.genre.split(','),
            'imdb_score': self.imdb_score,
            'views': self.views,
            'created_by': self.created_by,
            'created_at': self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            'updated_by': self.created_by,
            'updated_at': self.updated_at.strftime("%Y-%m-%d %H:%M:%S")
        }


class BlacklistToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False, index=True)
    blacklisted_on = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, token):
        self.token = token

    def __repr__(self):
        return '<id: token: {}'.format(self.token)
