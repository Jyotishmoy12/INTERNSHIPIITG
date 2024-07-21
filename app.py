from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

from routes import *
from models import User, StudentData, Passkey, PGStudentAdminPasskey, EquipmentAdminPasskey,SpaceAdminPasskey, SuperAdminPasskey

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Ensure the passkey tables have the initial passkeys set
        if not Passkey.query.first():
            initial_passkey = Passkey(passkey='123456')
            db.session.add(initial_passkey)
            db.session.commit()
        if not PGStudentAdminPasskey.query.first():
            initial_pg_passkey = PGStudentAdminPasskey(passkey='abcd')
            db.session.add(initial_pg_passkey)
            db.session.commit()
        if not EquipmentAdminPasskey.query.first():
            initial_equipment_passkey = EquipmentAdminPasskey(passkey='12')
            db.session.add(initial_equipment_passkey)
            db.session.commit()

        if not SpaceAdminPasskey.query.first():
            initial_space_admin_passkey = SpaceAdminPasskey(passkey='4321')
            db.session.add(initial_space_admin_passkey)
            db.session.commit()

        if not SuperAdminPasskey.query.first():
            initial_super_admin_passkey = SuperAdminPasskey(passkey='mars')
            db.session.add(initial_super_admin_passkey)
            db.session.commit()
    
    print("Database tables created and initial data added.")

    app.run(debug=True)