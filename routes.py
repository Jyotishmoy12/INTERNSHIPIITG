from flask import render_template, url_for, flash, redirect, request, jsonify,session, send_file,make_response
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User, StudentData, Passkey,PGStudentAdminPasskey,PGStudentData, EquipmentAdminPasskey, Equipment, SpaceAdminPasskey
import pandas as pd
import xlsxwriter
from io import BytesIO
from datetime import datetime
import io 

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
    if current_user.role not in ['student', 'admin', 'pg_student_admin', 'equipment_admin']:
        flash('Access denied. You must be a student, admin, PG student admin, or equipment admin to view this page.', 'danger')
        return redirect(url_for('home'))

    if current_user.role in ['admin', 'equipment_admin']:
        # For admin and equipment_admin, fetch all data without filtering
        student_data = StudentData.query.all()
        return render_template('student_dashboard.html', 
                               title='Student Dashboard', 
                               student_data=student_data,
                               user_role=current_user.role,
                               is_admin=True)
    else:
        # Existing logic for students and pg_student_admin
        student_data = StudentData.query.all()
        return render_template('student_dashboard.html', 
                               title='Student Dashboard', 
                               student_data=student_data,
                               user_role=current_user.role,
                               is_admin=False)


@app.route("/download_all_student_data")
@login_required
def download_all_student_data():
    if current_user.role not in ['admin', 'pg_student_admin', 'equipment_admin']:
        flash('Access denied. You must be an Admin, PG Student Admin, or Equipment Admin to download all data.', 'danger')
        return redirect(url_for('home'))

    student_data = StudentData.query.all()

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    headers = ['Name', 'Subject', 'Type', 'Subject Name', 'Instructor', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

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

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='all_student_data.xlsx'
    )


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

@app.route("/pg_student_admin_panel", methods=['GET', 'POST'])
@login_required
def pg_student_admin_panel():
    if current_user.role != 'pg_student_admin':
        flash('Access denied. You must be a PG Student Admin to view this page.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename.endswith('.xlsx'):
                df = pd.read_excel(file)
                for _, row in df.iterrows():
                    pg_student_data = PGStudentData(
                        student_name=row.get('Names', ''),
                        programme=row.get('Programme', ''),
                        comprehensive_exam_date=row.get('Comprehensive Exam Date', ''),
                        soas_date=row.get('SOAS Date', ''),
                        synopsis_date=row.get('Synopsis Date', ''),
                        defense_date=row.get('Defense Date', ''),
                        thesis_title=row.get('Thesis Title', ''),
                        supervisor=row.get('Supervisor', ''),
                        co_supervisor=row.get('Co-Supervisor', ''),
                        extra_column1='',
                        extra_column2=''
                    )
                    db.session.add(pg_student_data)
                db.session.commit()
                flash('Excel data uploaded successfully', 'success')
                return redirect(url_for('pg_student_dashboard'))
            else:
                flash('Invalid file format. Please upload an Excel file.', 'danger')
        else:
            # Manual data entry
            pg_student_data = PGStudentData(
                student_name=request.form['student_name'],
                programme=request.form['programme'],
                comprehensive_exam_date=request.form['comprehensive_exam_date'],
                soas_date=request.form['soas_date'],
                synopsis_date=request.form['synopsis_date'],
                defense_date=request.form['defense_date'],
                thesis_title=request.form['thesis_title'],
                supervisor=request.form['supervisor'],
                co_supervisor=request.form['co_supervisor'],
                extra_column1=request.form['extra_column1'],
                extra_column2=request.form['extra_column2']
            )
            db.session.add(pg_student_data)
            db.session.commit()
            flash('PG Student data added successfully', 'success')
            return redirect(url_for('pg_student_dashboard'))

    return render_template('pg_student_admin_panel.html', title='PG Student Admin Panel')

@app.route("/pg_student_dashboard", methods=['GET', 'POST'])
@login_required
def pg_student_dashboard():
    if current_user.role not in ['pg_student_admin', 'admin', 'equipment_admin']:
        flash('Access denied. You must be a PG Student Admin, Admin, or Equipment Admin to view this page.', 'danger')
        return redirect(url_for('home'))

    if current_user.role in ['admin', 'equipment_admin']:
        # For admin and equipment_admin, fetch all data without filtering
        pg_student_data = PGStudentData.query.all()
        programmes = db.session.query(PGStudentData.programme).distinct().all()
        programmes = [p[0] for p in programmes]
        return render_template('pg_student_dashboard.html', 
                               title='PG Student Dashboard', 
                               pg_student_data=pg_student_data,
                               programmes=programmes,
                               is_admin=True)
    else:
        # Existing filtering logic for pg_student_admin
        name_filter = request.args.get('name_filter', '')
        programme_filter = request.args.get('programme_filter', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        supervisor_filter = request.args.get('supervisor_filter', '')
        search_query = request.args.get('search_query', '')

        query = PGStudentData.query

        if name_filter:
            query = query.filter(PGStudentData.student_name.ilike(f'%{name_filter}%'))
        if programme_filter:
            query = query.filter(PGStudentData.programme == programme_filter)
        if supervisor_filter:
            query = query.filter(PGStudentData.supervisor.ilike(f'%{supervisor_filter}%'))
        if date_from and date_to:
            date_from = datetime.strptime(date_from, '%Y-%m-%d')
            date_to = datetime.strptime(date_to, '%Y-%m-%d')
            query = query.filter(
                (PGStudentData.comprehensive_exam_date.between(date_from, date_to)) |
                (PGStudentData.soas_date.between(date_from, date_to)) |
                (PGStudentData.synopsis_date.between(date_from, date_to)) |
                (PGStudentData.defense_date.between(date_from, date_to))
            )

        if search_query:
            query = query.filter(
                (PGStudentData.student_name.ilike(f'%{search_query}%')) |
                (PGStudentData.programme.ilike(f'%{search_query}%')) |
                (PGStudentData.thesis_title.ilike(f'%{search_query}%')) |
                (PGStudentData.supervisor.ilike(f'%{search_query}%')) |
                (PGStudentData.co_supervisor.ilike(f'%{search_query}%'))
            )

        pg_student_data = query.all()

        programmes = db.session.query(PGStudentData.programme).distinct().all()
        programmes = [p[0] for p in programmes]

        return render_template('pg_student_dashboard.html', 
                               title='PG Student Dashboard', 
                               pg_student_data=pg_student_data,
                               programmes=programmes,
                               name_filter=name_filter,
                               programme_filter=programme_filter,
                               date_from=date_from,
                               date_to=date_to,
                               supervisor_filter=supervisor_filter,
                               search_query=search_query,
                               is_admin=False)





@app.route("/download_all_pg_data")
@login_required
def download_all_pg_data():
    if current_user.role not in ['admin', 'pg_student_admin', 'equipment_admin']:
        flash('Access denied. You must be an Admin, PG Student Admin, or Equipment Admin to download all data.', 'danger')
        return redirect(url_for('home'))

    pg_student_data = PGStudentData.query.all()

    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    headers = ['Name', 'Programme', 'Comprehensive Exam Date', 'SOAS Date', 'Synopsis Date', 'Defense Date', 'Thesis Title', 'Supervisor', 'Co-Supervisor', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    def format_date(date_value):
        if isinstance(date_value, datetime):
            return date_value.strftime('%Y-%m-%d')
        elif isinstance(date_value, str):
            return date_value
        else:
            return ''

    for row, data in enumerate(pg_student_data, start=1):
        worksheet.write(row, 0, data.student_name)
        worksheet.write(row, 1, data.programme)
        worksheet.write(row, 2, format_date(data.comprehensive_exam_date))
        worksheet.write(row, 3, format_date(data.soas_date))
        worksheet.write(row, 4, format_date(data.synopsis_date))
        worksheet.write(row, 5, format_date(data.defense_date))
        worksheet.write(row, 6, data.thesis_title)
        worksheet.write(row, 7, data.supervisor)
        worksheet.write(row, 8, data.co_supervisor)
        worksheet.write(row, 9, data.extra_column1)
        worksheet.write(row, 10, data.extra_column2)

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='all_pg_student_data.xlsx'
    )

@app.route("/download_filtered_pg_data")
@login_required
def download_filtered_pg_data():
    if current_user.role not in ['pg_student_admin', 'admin']:
        flash('Access denied. You must be a PG Student Admin or Admin to download data.', 'danger')
        return redirect(url_for('home'))

    # Get filter and search parameters
    name_filter = request.args.get('name_filter', '')
    programme_filter = request.args.get('programme_filter', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    supervisor_filter = request.args.get('supervisor_filter', '')
    search_query = request.args.get('search_query', '')

    # Base query
    query = PGStudentData.query

    # Apply filters
    if name_filter:
        query = query.filter(PGStudentData.student_name.ilike(f'%{name_filter}%'))
    if programme_filter:
        query = query.filter(PGStudentData.programme == programme_filter)
    if supervisor_filter:
        query = query.filter(PGStudentData.supervisor.ilike(f'%{supervisor_filter}%'))
    if date_from and date_to:
        date_from = datetime.strptime(date_from, '%Y-%m-%d')
        date_to = datetime.strptime(date_to, '%Y-%m-%d')
        query = query.filter(
            (PGStudentData.comprehensive_exam_date.between(date_from, date_to)) |
            (PGStudentData.soas_date.between(date_from, date_to)) |
            (PGStudentData.synopsis_date.between(date_from, date_to)) |
            (PGStudentData.defense_date.between(date_from, date_to))
        )

    # Apply search
    if search_query:
        query = query.filter(
            (PGStudentData.student_name.ilike(f'%{search_query}%')) |
            (PGStudentData.programme.ilike(f'%{search_query}%')) |
            (PGStudentData.thesis_title.ilike(f'%{search_query}%')) |
            (PGStudentData.supervisor.ilike(f'%{search_query}%')) |
            (PGStudentData.co_supervisor.ilike(f'%{search_query}%'))
        )

    pg_student_data = query.all()

    # Create an in-memory output file
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Write headers
    headers = ['Name', 'Programme', 'Comprehensive Exam Date', 'SOAS Date', 'Synopsis Date', 'Defense Date', 'Thesis Title', 'Supervisor', 'Co-Supervisor', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Write data
    for row, data in enumerate(pg_student_data, start=1):
        worksheet.write(row, 0, data.student_name)
        worksheet.write(row, 1, data.programme)
        worksheet.write(row, 2, data.comprehensive_exam_date.strftime('%Y-%m-%d') if data.comprehensive_exam_date else '')
        worksheet.write(row, 3, data.soas_date.strftime('%Y-%m-%d') if data.soas_date else '')
        worksheet.write(row, 4, data.synopsis_date.strftime('%Y-%m-%d') if data.synopsis_date else '')
        worksheet.write(row, 5, data.defense_date.strftime('%Y-%m-%d') if data.defense_date else '')
        worksheet.write(row, 6, data.thesis_title)
        worksheet.write(row, 7, data.supervisor)
        worksheet.write(row, 8, data.co_supervisor)
        worksheet.write(row, 9, data.extra_column1)
        worksheet.write(row, 10, data.extra_column2)

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
       download_name='filtered_pg_student_data.xlsx'
    )


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

@app.route("/delete_pg_student_data/<int:id>", methods=['POST'])
@login_required
def delete_pg_student_data(id):
    if current_user.role not in ['pg_student_admin', 'admin']:
        flash('Access denied. You must be a PG Student Admin or Admin to delete data.', 'danger')
        return redirect(url_for('home'))
    pg_student_data = PGStudentData.query.get_or_404(id)
    db.session.delete(pg_student_data)
    db.session.commit()
    flash('PG Student data deleted successfully', 'success')
    return redirect(url_for('pg_student_dashboard'))

@app.route("/delete_all_pg_student_data", methods=['POST'])
@login_required
def delete_all_pg_student_data():
    if current_user.role not in ['pg_student_admin', 'admin']:
        flash('Access denied. You must be a PG Student Admin or Admin to delete all data.', 'danger')
        return redirect(url_for('home'))
    PGStudentData.query.delete()
    db.session.commit()
    flash('All PG Student data deleted successfully', 'success')
    return redirect(url_for('pg_student_admin_panel'))




# ... (keep all existing routes)

@app.route("/check_equipment_admin_passkey", methods=['POST'])
def check_equipment_admin_passkey():
    passkey = request.form['passkey']
    stored_passkey = EquipmentAdminPasskey.query.first()
    if stored_passkey and passkey == stored_passkey.passkey:
        session['equipment_admin_passkey_verified'] = True
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False})

@app.route("/equipment_admin_register", methods=['GET', 'POST'])
def equipment_admin_register():
    if not session.get('equipment_admin_passkey_verified'):
        flash('Please enter the Equipment Admin passkey first.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('equipment_admin_register.html', title='Equipment Admin Register')
        
        user = User(username=username, password=generate_password_hash(password), role='equipment_admin')
        db.session.add(user)
        db.session.commit()
        
        session.pop('equipment_admin_passkey_verified', None)  # Clear the session variable
        flash('Your Equipment Admin account has been created! You can now log in.', 'success')
        return redirect(url_for('equipment_admin_login'))
    
    return render_template('equipment_admin_register.html', title='Equipment Admin Register')

@app.route("/equipment_admin_login", methods=['GET', 'POST'])
def equipment_admin_login():
    if current_user.is_authenticated and current_user.role == 'equipment_admin':
        return redirect(url_for('equipment_admin_panel'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='equipment_admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('equipment_admin_panel'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('equipment_admin_login.html', title='Equipment Admin Login')

@app.route("/equipment_admin_panel", methods=['GET', 'POST'])
@login_required
def equipment_admin_panel():
    if current_user.role != 'equipment_admin':
        flash('Access denied. You must be an Equipment Admin to view this page.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename.endswith('.xlsx'):
                df = pd.read_excel(file)
                for _, row in df.iterrows():
                    equipment = Equipment(
                        sl_no=str(row.get('Sl No', '')),
                        description=str(row.get('Description of Item', '')),
                        po_no_date=str(row.get('P.O. No.with Date', '')),
                        quantity=str(row.get('Qty.', '')),
                        price=str(row.get('Price mentioned in the Asset Register', '')),
                        location=str(row.get('Location', '')),
                        dept_stock_register_no=str(row.get('Dept. Stock Register No.', '')),
                        status=str(row.get('Status', '')),
                        remarks=str(row.get('Remarks', '')),
                        extra_column1='',
                        extra_column2=''
                    )
                    db.session.add(equipment)
                db.session.commit()
                flash('Excel data uploaded successfully', 'success')
            else:
                flash('Invalid file format. Please upload an Excel file.', 'danger')
        else:
            # Manual data entry
            equipment = Equipment(
                # sl_no=request.form['sl_no'],
                description=request.form['description'],
                po_no_date=request.form['po_no_date'],
                quantity=request.form['quantity'],
                price=request.form['price'],
                location=request.form['location'],
                dept_stock_register_no=request.form['dept_stock_register_no'],
                status=request.form['status'],
                remarks=request.form['remarks'],
                extra_column1=request.form['extra_column1'],
                extra_column2=request.form['extra_column2']
            )
            db.session.add(equipment)
            db.session.commit()
            flash('Equipment data added successfully', 'success')

    equipment_data = Equipment.query.all()
    return render_template('equipment_admin_panel.html', title='Equipment Admin Panel', equipment_data=equipment_data)

@app.route("/equipment_admin_forgot_password", methods=['GET', 'POST'])
def equipment_admin_forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        admin_passkey = request.form['admin_passkey']
        
        stored_passkey = EquipmentAdminPasskey.query.first()
        if not stored_passkey or admin_passkey != stored_passkey.passkey:
            flash('Invalid Equipment Admin passkey. Please try again.', 'danger')
            return render_template('equipment_admin_forgot_password.html', title='Equipment Admin Forgot Password')
        
        user = User.query.filter_by(username=username, role='equipment_admin').first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your Equipment Admin password has been updated. You can now log in with your new password.', 'success')
            return redirect(url_for('equipment_admin_login'))
        else:
            flash('Equipment Admin username not found. Please check and try again.', 'danger')
    return render_template('equipment_admin_forgot_password.html', title='Equipment Admin Forgot Password')

@app.route("/set_equipment_admin_passkey", methods=['POST'])
@login_required
def set_equipment_admin_passkey():
    if current_user.role != 'equipment_admin':
        flash('Access denied. You must be an Equipment Admin to set a new passkey.', 'danger')
        return redirect(url_for('home'))
    
    new_passkey = request.form['new_passkey']
    passkey = EquipmentAdminPasskey.query.first()
    if passkey:
        passkey.passkey = new_passkey
    else:
        passkey = EquipmentAdminPasskey(passkey=new_passkey)
        db.session.add(passkey)
    db.session.commit()
    
    flash('Equipment Admin Passkey updated successfully', 'success')
    return redirect(url_for('equipment_admin_panel'))

@app.route("/delete_equipment/<int:id>", methods=['POST'])
@login_required
def delete_equipment(id):
    if current_user.role != 'equipment_admin':
        flash('Access denied. You must be an Equipment Admin to delete equipment data.', 'danger')
        return redirect(url_for('home'))
    equipment = Equipment.query.get_or_404(id)
    db.session.delete(equipment)
    db.session.commit()
    flash('Equipment data deleted successfully', 'success')
    return redirect(url_for('equipment_dashboard'))



@app.route("/equipment_dashboard")
@login_required
def equipment_dashboard():
    if current_user.role not in ['equipment_admin', 'admin']:
        flash('Access denied. You must be an Equipment Admin or Admin to view this page.', 'danger')
        return redirect(url_for('home'))
    query = Equipment.query
    page = request.args.get('page', 1, type=int)
    equipment_data = query.paginate(page=page, per_page=10)

    return render_template('equipment_dashboard.html', 
                           title='Equipment Dashboard', 
                           equipment_data=equipment_data)


@app.route("/delete_all_equipment", methods=['POST'])
@login_required
def delete_all_equipment():
    if current_user.role != 'equipment_admin':
        flash('Access denied. You must be an Equipment Admin to delete all equipment data.', 'danger')
        return redirect(url_for('home'))
    
    Equipment.query.delete()
    db.session.commit()
    flash('All equipment data has been deleted successfully', 'success')
    return redirect(url_for('equipment_admin_panel'))


@app.route('/download_filtered_equipment_data')
def download_filtered_equipment_data():
    search_query = request.args.get('search_query', '')
    status_filter = request.args.get('status_filter', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')

    # Apply filters to your query
    query = Equipment.query
    if search_query:
        query = query.filter(Equipment.description.ilike(f'%{search_query}%'))
    if status_filter:
        query = query.filter(Equipment.status == status_filter)
    if date_from and date_to:
        query = query.filter(Equipment.po_no_date.between(date_from, date_to))

    # Get filtered data
    filtered_data = query.all()

    # Create Excel file
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()

    # Write headers
    headers = ['Description', 'P.O. No. with Date', 'Qty.', 'Price', 'Location', 'Dept. Stock Register No.', 'Status', 'Remarks', 'Extra Column 1', 'Extra Column 2']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)

    # Write data
    for row, equipment in enumerate(filtered_data, start=1):
        worksheet.write(row, 0, equipment.description)
        worksheet.write(row, 1, equipment.po_no_date)
        worksheet.write(row, 2, equipment.quantity)
        worksheet.write(row, 3, equipment.price)
        worksheet.write(row, 4, equipment.location)
        worksheet.write(row, 5, equipment.dept_stock_register_no)
        worksheet.write(row, 6, equipment.status)
        worksheet.write(row, 7, equipment.remarks)
        worksheet.write(row, 8, equipment.extra_column1)
        worksheet.write(row, 9, equipment.extra_column2)

    workbook.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='filtered_equipment_data.xlsx'
    )


@app.route('/check_space_admin_passkey', methods=['POST'])
def check_space_admin_passkey():
    passkey = request.form.get('passkey')
    valid_passkey = SpaceAdminPasskey.query.first()
    
    if valid_passkey and passkey == valid_passkey.passkey:
        return jsonify({'valid': True})
    return jsonify({'valid': False})

@app.route('/space_admin_register', methods=['GET', 'POST'])
def space_admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists', 'error')
            return redirect(url_for('space_admin_register'))
        
        new_user = User(username=username, password=generate_password_hash(password), role='space_admin')
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('space_admin_login'))
    
    return render_template('space_admin_register.html')

@app.route('/space_admin_login', methods=['GET', 'POST'])
def space_admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, role='space_admin').first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('space_admin_panel'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('space_admin_login.html')

@app.route('/space_admin_panel')
@login_required
def space_admin_panel():
    if current_user.role != 'space_admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('login'))
    
    return render_template('space_admin_panel.html')


@app.route("/space_admin_forgot_password", methods=['GET', 'POST'])
def space_admin_forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        admin_passkey = request.form['admin_passkey']
        
        stored_passkey = SpaceAdminPasskey.query.first()
        if not stored_passkey or admin_passkey != stored_passkey.passkey:
            flash('Invalid Space Admin passkey. Please try again.', 'danger')
            return render_template('space_admin_forgot_password.html', title='Space Admin Forgot Password')
        
        user = User.query.filter_by(username=username, role='space_admin').first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Your Space Admin password has been updated. You can now log in with your new password.', 'success')
            return redirect(url_for('space_admin_login'))
        else:
            flash('Space Admin username not found. Please check and try again.', 'danger')
    return render_template('space_admin_forgot_password.html', title='Space Admin Forgot Password')