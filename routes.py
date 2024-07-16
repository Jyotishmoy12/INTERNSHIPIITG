from flask import render_template, url_for, flash, redirect, request, jsonify,session, send_file,make_response
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User, StudentData, Passkey,PGStudentAdminPasskey
import pandas as pd
import xlsxwriter
from io import BytesIO


@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'student'
        user = User(username=username, password=generate_password_hash(password), role=role)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('student_dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('student_dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your password has been updated. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username not found. Please check and try again.', 'danger')
    return render_template('forgot_password.html', title='Forgot Password')

@app.route("/student_dashboard")
@login_required
def student_dashboard():
    if current_user.role not in ['student', 'admin', 'pg_student_admin']:
        flash('Access denied. You must be a student or admin to view this page.', 'danger')
        return redirect(url_for('home'))

    student_data = StudentData.query.all()
    
    return render_template('student_dashboard.html', 
                           title='Student Dashboard', 
                           student_data=student_data,
                           user_role=current_user.role)


@app.route("/download_filtered_data")
@login_required
def download_filtered_data():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to download data.', 'danger')
        return redirect(url_for('home'))

    type_filter = request.args.get('type_filter', '')
    
    if type_filter:
        student_data = StudentData.query.filter_by(subject_type=type_filter).all()
    else:
        student_data = StudentData.query.all()

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Write headers
    headers = ['Name', 'Subject', 'Type', 'Subject Name', 'Instructor', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Write data
    for row, data in enumerate(student_data, start=1):
        worksheet.write(row, 0, data.student_name)
        worksheet.write(row, 1, data.subject)
        worksheet.write(row, 2, data.subject_type)
        worksheet.write(row, 3, data.subject_name)
        worksheet.write(row, 4, data.instructor)
        worksheet.write(row, 5, data.extra_column1)
        worksheet.write(row, 6, data.extra_column2)

    workbook.close()
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = 'attachment; filename=filtered_student_data.xlsx'

    return response


@app.route("/download_all_data")
@login_required
def download_all_data():
    if current_user.role not in ['admin', 'pg_student_admin']:
        flash('Access denied. You must be an admin or PG Student Admin to download data.', 'danger')
        return redirect(url_for('home'))

    student_data = StudentData.query.all()

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Write headers
    headers = ['Name', 'Subject', 'Type', 'Subject Name', 'Instructor', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Write data
    for row, data in enumerate(student_data, start=1):
        worksheet.write(row, 0, data.student_name)
        worksheet.write(row, 1, data.subject)
        worksheet.write(row, 2, data.subject_type)
        worksheet.write(row, 3, data.subject_name)
        worksheet.write(row, 4, data.instructor)
        worksheet.write(row, 5, data.extra_column1)
        worksheet.write(row, 6, data.extra_column2)

    workbook.close()
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    response.headers['Content-Disposition'] = 'attachment; filename=all_student_data.xlsx'

    return response


@app.route("/admin_panel")
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to view this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_panel.html', title='Admin Panel')

@app.route("/teaching_assistant_dashboard")
@login_required
def teaching_assistant_dashboard():
    if current_user.role not in ['teaching_assistant', 'admin']:
        flash('Access denied. You must be a teaching assistant or admin to view this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('teaching_assistant_dashboard.html', title='Teaching Assistant Dashboard')

@app.route("/admin_register", methods=['GET', 'POST'])
def admin_register():
    if not session.get('admin_passkey_verified'):
        flash('Please enter the admin passkey first.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('admin_register.html', title='Admin Register')
        
        user = User(username=username, password=generate_password_hash(password), role='admin')
        db.session.add(user)
        db.session.commit()
        
        session.pop('admin_passkey_verified', None)  # Clear the session variable
        flash('Your admin account has been created! You can now log in.', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('admin_register.html', title='Admin Register')

@app.route("/check_admin_passkey", methods=['POST'])
def check_admin_passkey():
    passkey = request.form['passkey']
    stored_passkey = Passkey.query.first()
    if stored_passkey and passkey == stored_passkey.passkey:
        session['admin_passkey_verified'] = True
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False})


@app.route("/set_passkey", methods=['POST'])
@login_required
def set_passkey():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to set a new passkey.', 'danger')
        return redirect(url_for('home'))
    
    new_passkey = request.form['new_passkey']
    passkey = Passkey.query.first()
    if passkey:
        passkey.passkey = new_passkey
    else:
        passkey = Passkey(passkey=new_passkey)
        db.session.add(passkey)
    db.session.commit()
    
    flash('Passkey updated successfully', 'success')
    return redirect(url_for('admin_panel'))

@app.route("/admin_login", methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.role == 'admin':
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_panel'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('admin_login.html', title='Admin Login')



@app.route("/admin_forgot_password", methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        admin_passkey = request.form['admin_passkey']
        
        stored_passkey = Passkey.query.first()
        if not stored_passkey or admin_passkey != stored_passkey.passkey:
            flash('Invalid admin passkey. Please try again.', 'danger')
            return render_template('admin_forgot_password.html', title='Admin Forgot Password')
        
        user = User.query.filter_by(username=username, role='admin').first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your admin password has been updated. You can now log in with your new password.', 'success')
            return redirect(url_for('admin_login'))
        else:
            flash('Admin username not found. Please check and try again.', 'danger')
    return render_template('admin_forgot_password.html', title='Admin Forgot Password')

@app.route("/upload_excel", methods=['POST'])
@login_required
def upload_excel():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to upload data.', 'danger')
        return redirect(url_for('home'))
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('admin_panel'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('admin_panel'))
    if file:
        df = pd.read_excel(file)
        df.dropna(how='any', inplace=True)
        for _, row in df.iterrows():
            student_data = StudentData(
                student_name=row['Names'],
                subject=row['Subject'],
                subject_type=row['Type'],
                subject_name=row['Subject Name'],
                instructor=row['Instructor']
            )
            db.session.add(student_data)
        db.session.commit()
        flash('Excel data uploaded successfully', 'success')
    return redirect(url_for('student_dashboard'))

@app.route("/add_student_data", methods=['POST'])
@login_required
def add_student_data():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to add student data.', 'danger')
        return redirect(url_for('home'))
    student_data = StudentData(
        student_name=request.form['student_name'],
        subject=request.form['subject'],
        subject_type=request.form['subject_type'],
        subject_name=request.form['subject_name'],
        instructor=request.form['instructor'],
        extra_column1=request.form['extra_column1'],
        extra_column2=request.form['extra_column2']
    )
    db.session.add(student_data)
    db.session.commit()
    flash('Student data added successfully', 'success')
    return redirect(url_for('admin_panel'))

@app.route("/delete_student_data/<int:id>", methods=['POST'])
@login_required
def delete_student_data(id):
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to delete student data.', 'danger')
        return redirect(url_for('home'))
    student_data = StudentData.query.get_or_404(id)
    db.session.delete(student_data)
    db.session.commit()
    flash('Student data deleted successfully', 'success')
    return redirect(url_for('student_dashboard'))

@app.route("/delete_all_student_data", methods=['POST'])
@login_required
def delete_all_student_data():
    if current_user.role != 'admin':
        flash('Access denied. You must be an admin to delete all student data.', 'danger')
        return redirect(url_for('home'))
    StudentData.query.delete()
    db.session.commit()
    flash('All student data deleted successfully', 'success')
    return redirect(url_for('admin_panel'))

@app.route("/pg_student_admin_register", methods=['GET', 'POST'])
def pg_student_admin_register():
    if not session.get('pg_student_admin_passkey_verified'):
        flash('Please enter the PG Student Admin passkey first.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('pg_student_admin_register.html', title='PG Student Admin Register')
        
        user = User(username=username, password=generate_password_hash(password), role='pg_student_admin')
        db.session.add(user)
        db.session.commit()
        
        session.pop('pg_student_admin_passkey_verified', None)  # Clear the session variable
        flash('Your PG Student Admin account has been created! You can now log in.', 'success')
        return redirect(url_for('pg_student_admin_login'))
    
    return render_template('pg_student_admin_register.html', title='PG Student Admin Register')

@app.route("/check_pg_student_admin_passkey", methods=['POST'])
def check_pg_student_admin_passkey():
    passkey = request.form['passkey']
    stored_passkey = PGStudentAdminPasskey.query.first()
    if stored_passkey and passkey == stored_passkey.passkey:
        session['pg_student_admin_passkey_verified'] = True
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False})

@app.route("/pg_student_admin_login", methods=['GET', 'POST'])
def pg_student_admin_login():
    if current_user.is_authenticated and current_user.role == 'pg_student_admin':
        return redirect(url_for('pg_student_admin_panel'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='pg_student_admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('pg_student_admin_panel'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('pg_student_admin_login.html', title='PG Student Admin Login')

@app.route("/pg_student_admin_panel")
@login_required
def pg_student_admin_panel():
    if current_user.role != 'pg_student_admin':
        flash('Access denied. You must be a PG Student Admin to view this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('pg_student_admin_panel.html', title='PG Student Admin Panel')

@app.route("/pg_student_admin_forgot_password", methods=['GET', 'POST'])
def pg_student_admin_forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        admin_passkey = request.form['admin_passkey']
        
        stored_passkey = PGStudentAdminPasskey.query.first()
        if not stored_passkey or admin_passkey != stored_passkey.passkey:
            flash('Invalid PG Student Admin passkey. Please try again.', 'danger')
            return render_template('pg_student_admin_forgot_password.html', title='PG Student Admin Forgot Password')
        
        user = User.query.filter_by(username=username, role='pg_student_admin').first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your PG Student Admin password has been updated. You can now log in with your new password.', 'success')
            return redirect(url_for('pg_student_admin_login'))
        else:
            flash('PG Student Admin username not found. Please check and try again.', 'danger')
    return render_template('pg_student_admin_forgot_password.html', title='PG Student Admin Forgot Password')

@app.route("/set_pg_student_admin_passkey", methods=['POST'])
@login_required
def set_pg_student_admin_passkey():
    if current_user.role != 'pg_student_admin':
        flash('Access denied. You must be a PG Student Admin to set a new passkey.', 'danger')
        return redirect(url_for('home'))
    
    new_passkey = request.form['new_passkey']
    passkey = PGStudentAdminPasskey.query.first()
    if passkey:
        passkey.passkey = new_passkey
    else:
        passkey = PGStudentAdminPasskey(passkey=new_passkey)
        db.session.add(passkey)
    db.session.commit()
    
    flash('PG Student Admin Passkey updated successfully', 'success')
    return redirect(url_for('pg_student_admin_panel'))