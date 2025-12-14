from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    verifications = db.relationship('Verification', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500))
    truth_score = db.Column(db.Integer)
    false_score = db.Column(db.Integer)
    classification = db.Column(db.String(64))
    explanation = db.Column(db.Text)
    source_id = db.Column(db.Integer, db.ForeignKey('source.id'))
    source_obj = db.relationship('Source', backref='verifications')
    source = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))



class Source(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), unique=True, nullable=False)
    source_type = db.Column(db.String(64), nullable=False) # e.g., 'Website', 'Facebook Post', 'Tweet'
    title = db.Column(db.String(256))
    author = db.Column(db.String(128))
    published_date = db.Column(db.DateTime)
    retrieved_date = db.Column(db.DateTime, default=datetime.utcnow)
    extra_data = db.Column(db.Text) # Storing additional JSON metadata if needed

    def __repr__(self):
        return f'<Source {self.url}>'

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
