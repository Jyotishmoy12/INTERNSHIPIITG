from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class StudentData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    subject_type = db.Column(db.String(50))
    subject_name = db.Column(db.String(100))
    instructor = db.Column(db.String(100))
    extra_column1 = db.Column(db.String(100))
    extra_column2 = db.Column(db.String(100))

class PGStudentData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_name = db.Column(db.String(100), nullable=False)
    programme = db.Column(db.String(100))
    comprehensive_exam_date = db.Column(db.String(100))
    soas_date = db.Column(db.String(100))
    synopsis_date = db.Column(db.String(100))
    defense_date = db.Column(db.String(100))
    thesis_title = db.Column(db.String(200))
    supervisor = db.Column(db.String(100))
    co_supervisor = db.Column(db.String(100))
    extra_column1 = db.Column(db.String(100))
    extra_column2 = db.Column(db.String(100))


class Passkey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passkey = db.Column(db.String(20), nullable=False)

class PGStudentAdminPasskey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passkey = db.Column(db.String(20), nullable=False)