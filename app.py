from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
import sqlite3
import hashlib
import os
import uuid
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'admin'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'student'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'task_files'), exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect('grg_platform.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            user_type TEXT NOT NULL,
            student_id TEXT,
            department TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Files table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_by INTEGER,
            uploaded_for TEXT DEFAULT 'all',
            file_size INTEGER,
            file_type TEXT,
            description TEXT,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
    ''')
    
    # Tasks table with file support
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            assigned_by INTEGER,
            assigned_to INTEGER,
            due_date DATE,
            status TEXT DEFAULT 'pending',
            priority TEXT DEFAULT 'medium',
            task_file_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (assigned_by) REFERENCES users (id),
            FOREIGN KEY (assigned_to) REFERENCES users (id),
            FOREIGN KEY (task_file_id) REFERENCES files (id)
        )
    ''')
    
    # Timeline table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            event_date DATE NOT NULL,
            event_type TEXT DEFAULT 'milestone',
            status TEXT DEFAULT 'upcoming',
            details TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Task submissions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS task_submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER,
            submitted_by INTEGER,
            file_id INTEGER,
            submission_text TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'submitted',
            feedback TEXT,
            grade TEXT,
            FOREIGN KEY (task_id) REFERENCES tasks (id),
            FOREIGN KEY (submitted_by) REFERENCES users (id),
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    conn = sqlite3.connect('grg_platform.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = hash_password(request.form['password'])
        user_type = request.form['user_type']
        student_id = request.form.get('student_id', '')
        department = request.form.get('department', '')
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (name, email, password, user_type, student_id, department)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, email, password, user_type, student_id, department))
            conn.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_type = request.form['user_type']
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        conn = get_db_connection()
        user = conn.execute('''
            SELECT * FROM users WHERE email = ? AND password = ? AND user_type = ?
        ''', (email, password, user_type)).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_type'] = user['user_type']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user_type = session['user_type']
    
    if user_type == 'admin':
        return render_template('admin_dashboard.html')
    elif user_type == 'student':
        return render_template('student_dashboard.html')
    elif user_type == 'faculty':
        return render_template('faculty_dashboard.html')
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    description = request.form.get('description', '')
    uploaded_for = request.form.get('uploaded_for', 'all')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        original_filename = file.filename
        filename = str(uuid.uuid4()) + '_' + secure_filename(original_filename)
        
        # Create user-specific folder
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['user_type'])
        os.makedirs(user_folder, exist_ok=True)
        
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)
        
        # Save file info to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (filename, original_filename, file_path, uploaded_by, uploaded_for, 
                             file_size, file_type, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (filename, original_filename, file_path, session['user_id'], uploaded_for,
              os.path.getsize(file_path), file.content_type, description))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'File uploaded successfully', 'filename': original_filename, 'file_id': file_id})
    
    return jsonify({'error': 'Upload failed'}), 400

@app.route('/upload_task_file', methods=['POST'])
def upload_task_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    description = request.form.get('description', '')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        original_filename = file.filename
        filename = str(uuid.uuid4()) + '_' + secure_filename(original_filename)
        
        # Create task files folder
        task_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'task_files')
        os.makedirs(task_folder, exist_ok=True)
        
        file_path = os.path.join(task_folder, filename)
        file.save(file_path)
        
        # Save file info to database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (filename, original_filename, file_path, uploaded_by, uploaded_for, 
                             file_size, file_type, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (filename, original_filename, file_path, session['user_id'], 'task_file',
              os.path.getsize(file_path), file.content_type, description))
        file_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Task file uploaded successfully', 'filename': original_filename, 'file_id': file_id})
    
    return jsonify({'error': 'Upload failed'}), 400

@app.route('/files')
def files():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get files based on user type
    if session['user_type'] == 'admin':
        # Admin can see all files
        files = conn.execute('''
            SELECT f.*, u.name as uploaded_by_name, u.user_type as uploader_type, u.student_id
            FROM files f
            JOIN users u ON f.uploaded_by = u.id
            WHERE f.uploaded_for != 'task_file'
            ORDER BY f.upload_date DESC
        ''').fetchall()
    else:
        # Students/Faculty see files uploaded by admin and their own files
        files = conn.execute('''
            SELECT f.*, u.name as uploaded_by_name, u.user_type as uploader_type, u.student_id
            FROM files f
            JOIN users u ON f.uploaded_by = u.id
            WHERE ((u.user_type = 'admin' AND (f.uploaded_for = 'all' OR f.uploaded_for = ?))
               OR f.uploaded_by = ?) AND f.uploaded_for != 'task_file'
            ORDER BY f.upload_date DESC
        ''', (session['user_type'], session['user_id'])).fetchall()
    
    conn.close()
    return render_template('files.html', files=files)

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    file_record = conn.execute('''
        SELECT f.*, u.user_type as uploader_type
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        WHERE f.id = ?
    ''', (file_id,)).fetchone()
    conn.close()
    
    if not file_record:
        flash('File not found!', 'error')
        return redirect(url_for('files'))
    
    # Check permissions
    if (session['user_type'] != 'admin' and 
        file_record['uploaded_by'] != session['user_id'] and
        file_record['uploader_type'] != 'admin' and
        file_record['uploaded_for'] != session['user_type']):
        flash('Access denied!', 'error')
        return redirect(url_for('files'))
    
    try:
        return send_file(file_record['file_path'], 
                        as_attachment=True, 
                        download_name=file_record['original_filename'])
    except FileNotFoundError:
        flash('File not found on server!', 'error')
        return redirect(url_for('files'))

@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if session['user_type'] == 'admin':
        # Admin sees all tasks they created with file info
        tasks = conn.execute('''
            SELECT t.*, u.name as assigned_to_name, u.email as assigned_to_email, u.student_id,
                   f.original_filename as task_file_name, f.id as task_file_id
            FROM tasks t
            JOIN users u ON t.assigned_to = u.id
            LEFT JOIN files f ON t.task_file_id = f.id
            WHERE t.assigned_by = ?
            ORDER BY t.created_at DESC
        ''', (session['user_id'],)).fetchall()
    else:
        # Students/Faculty see tasks assigned to them with file info
        tasks = conn.execute('''
            SELECT t.*, u.name as assigned_by_name,
                   f.original_filename as task_file_name, f.id as task_file_id
            FROM tasks t
            JOIN users u ON t.assigned_by = u.id
            LEFT JOIN files f ON t.task_file_id = f.id
            WHERE t.assigned_to = ?
            ORDER BY t.created_at DESC
        ''', (session['user_id'],)).fetchall()
    
    # Get all users for task assignment (admin only)
    users = []
    if session['user_type'] == 'admin':
        users = conn.execute('''
            SELECT id, name, email, user_type, student_id, department
            FROM users
            WHERE user_type IN ('student', 'faculty')
            ORDER BY name
        ''').fetchall()
    
    conn.close()
    return render_template('tasks.html', tasks=tasks, users=users)

@app.route('/create_task', methods=['POST'])
def create_task():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    title = request.form['title']
    description = request.form['description']
    assigned_to = request.form['assigned_to']
    due_date = request.form['due_date']
    priority = request.form['priority']
    task_file_id = request.form.get('task_file_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO tasks (title, description, assigned_by, assigned_to, due_date, priority, task_file_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (title, description, session['user_id'], assigned_to, due_date, priority, task_file_id if task_file_id else None))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Task created successfully!'})

@app.route('/update_task_status', methods=['POST'])
def update_task_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    task_id = request.form['task_id']
    status = request.form['status']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE tasks SET status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND (assigned_to = ? OR assigned_by = ?)
    ''', (status, task_id, session['user_id'], session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Status updated successfully'})

@app.route('/submit_task', methods=['POST'])
def submit_task():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    task_id = request.form['task_id']
    submission_text = request.form.get('submission_text', '')
    file_id = request.form.get('file_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if submission already exists
    existing = cursor.execute('''
        SELECT id FROM task_submissions WHERE task_id = ? AND submitted_by = ?
    ''', (task_id, session['user_id'])).fetchone()
    
    if existing:
        # Update existing submission
        cursor.execute('''
            UPDATE task_submissions 
            SET file_id = ?, submission_text = ?, submitted_at = CURRENT_TIMESTAMP, status = 'submitted'
            WHERE task_id = ? AND submitted_by = ?
        ''', (file_id, submission_text, task_id, session['user_id']))
    else:
        # Create new submission
        cursor.execute('''
            INSERT INTO task_submissions (task_id, submitted_by, file_id, submission_text)
            VALUES (?, ?, ?, ?)
        ''', (task_id, session['user_id'], file_id, submission_text))
    
    # Update task status to in-progress
    cursor.execute('''
        UPDATE tasks SET status = 'in-progress', updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (task_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Task submitted successfully!'})

@app.route('/timeline')
def timeline():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    timeline_events = conn.execute('''
        SELECT t.*, u.name as created_by_name
        FROM timeline t
        LEFT JOIN users u ON t.created_by = u.id
        ORDER BY t.event_date ASC
    ''').fetchall()
    conn.close()
    
    return render_template('timeline.html', timeline_events=timeline_events)

@app.route('/create_timeline_event', methods=['POST'])
def create_timeline_event():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    title = request.form['title']
    description = request.form['description']
    event_date = request.form['event_date']
    event_type = request.form['event_type']
    details = request.form.get('details', '')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO timeline (title, description, event_date, event_type, details, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (title, description, event_date, event_type, details, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Timeline event created successfully!', 'success')
    return redirect(url_for('timeline'))

@app.route('/api/stats')
def api_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    
    if session['user_type'] == 'admin':
        # Admin stats
        total_users = conn.execute('SELECT COUNT(*) as count FROM users WHERE user_type != "admin"').fetchone()['count']
        total_files = conn.execute('SELECT COUNT(*) as count FROM files WHERE uploaded_for != "task_file"').fetchone()['count']
        pending_tasks = conn.execute('SELECT COUNT(*) as count FROM tasks WHERE status = "pending"').fetchone()['count']
        completed_tasks = conn.execute('SELECT COUNT(*) as count FROM tasks WHERE status = "completed"').fetchone()['count']
        
        stats = {
            'total_users': total_users,
            'total_files': total_files,
            'pending_tasks': pending_tasks,
            'completed_tasks': completed_tasks
        }
    else:
        # Student/Faculty stats
        my_tasks = conn.execute('SELECT COUNT(*) as count FROM tasks WHERE assigned_to = ?', (session['user_id'],)).fetchone()['count']
        pending_tasks = conn.execute('SELECT COUNT(*) as count FROM tasks WHERE assigned_to = ? AND status = "pending"', (session['user_id'],)).fetchone()['count']
        completed_tasks = conn.execute('SELECT COUNT(*) as count FROM tasks WHERE assigned_to = ? AND status = "completed"', (session['user_id'],)).fetchone()['count']
        my_files = conn.execute('SELECT COUNT(*) as count FROM files WHERE uploaded_by = ? AND uploaded_for != "task_file"', (session['user_id'],)).fetchone()['count']
        
        stats = {
            'my_tasks': my_tasks,
            'pending_tasks': pending_tasks,
            'completed_tasks': completed_tasks,
            'my_files': my_files
        }
    
    conn.close()
    return jsonify(stats)

# Faculty-specific API routes
@app.route('/api/faculty_stats')
def api_faculty_stats():
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get total students
    total_students = conn.execute('SELECT COUNT(*) as count FROM users WHERE user_type = "student"').fetchone()['count']
    
    # Get total submissions from students
    total_submissions = conn.execute('''
        SELECT COUNT(*) as count FROM files f
        JOIN users u ON f.uploaded_by = u.id
        WHERE u.user_type = 'student' AND f.uploaded_for = 'admin'
    ''').fetchone()['count']
    
    # Get pending reviews (submissions without feedback)
    pending_reviews = conn.execute('''
        SELECT COUNT(*) as count FROM task_submissions ts
        WHERE ts.feedback IS NULL OR ts.feedback = ""
    ''').fetchone()['count']
    
    # Get completed reviews
    completed_reviews = conn.execute('''
        SELECT COUNT(*) as count FROM task_submissions ts
        WHERE ts.feedback IS NOT NULL AND ts.feedback != ""
    ''').fetchone()['count']
    
    stats = {
        'total_students': total_students,
        'total_submissions': total_submissions,
        'pending_reviews': pending_reviews,
        'completed_reviews': completed_reviews
    }
    
    conn.close()
    return jsonify(stats)

@app.route('/api/student_progress')
def api_student_progress():
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get all students with their task progress
    students = conn.execute('''
        SELECT u.id, u.name, u.email, u.student_id, u.department,
               COUNT(DISTINCT t.id) as total_tasks,
               COUNT(DISTINCT CASE WHEN t.status = 'completed' THEN t.id END) as completed_tasks,
               COUNT(DISTINCT CASE WHEN t.status = 'pending' THEN t.id END) as pending_tasks,
               COUNT(DISTINCT ts.id) as total_submissions
        FROM users u
        LEFT JOIN tasks t ON u.id = t.assigned_to
        LEFT JOIN task_submissions ts ON u.id = ts.submitted_by
        WHERE u.user_type = 'student'
        GROUP BY u.id, u.name, u.email, u.student_id, u.department
        ORDER BY u.name
    ''').fetchall()
    
    conn.close()
    return jsonify([dict(student) for student in students])

@app.route('/api/faculty_submissions')
def api_faculty_submissions():
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get student submissions with task and review information
    submissions = conn.execute('''
        SELECT f.*, u.name as uploaded_by_name, u.student_id, u.department, u.email,
               ts.id as submission_id, ts.task_id, t.title as task_title, 
               ts.submission_text, ts.submitted_at, ts.feedback, ts.grade
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        LEFT JOIN task_submissions ts ON f.id = ts.file_id
        LEFT JOIN tasks t ON ts.task_id = t.id
        WHERE u.user_type = 'student' AND f.uploaded_for = 'admin'
        ORDER BY f.upload_date DESC
    ''').fetchall()
    
    conn.close()
    return jsonify([dict(submission) for submission in submissions])

@app.route('/api/all_student_tasks')
def api_all_student_tasks():
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get all tasks assigned to students with submission status
    tasks = conn.execute('''
        SELECT t.*, u.name as assigned_to_name, u.student_id,
               f.original_filename as task_file_name, f.id as task_file_id,
               ts.id as submission_id, ts.status as submission_status,
               sf.original_filename as submission_file_name, sf.id as submission_file_id
        FROM tasks t
        JOIN users u ON t.assigned_to = u.id
        LEFT JOIN files f ON t.task_file_id = f.id
        LEFT JOIN task_submissions ts ON t.id = ts.task_id
        LEFT JOIN files sf ON ts.file_id = sf.id
        WHERE u.user_type = 'student'
        ORDER BY t.created_at DESC
    ''').fetchall()
    
    conn.close()
    return jsonify([dict(task) for task in tasks])

@app.route('/api/student_detail/<int:student_id>')
def api_student_detail(student_id):
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get detailed student information
    student = conn.execute('''
        SELECT u.id, u.name, u.email, u.student_id, u.department,
               COUNT(DISTINCT t.id) as total_tasks,
               COUNT(DISTINCT CASE WHEN t.status = 'completed' THEN t.id END) as completed_tasks,
               COUNT(DISTINCT CASE WHEN t.status = 'pending' THEN t.id END) as pending_tasks,
               COUNT(DISTINCT ts.id) as total_submissions
        FROM users u
        LEFT JOIN tasks t ON u.id = t.assigned_to
        LEFT JOIN task_submissions ts ON u.id = ts.submitted_by
        WHERE u.id = ? AND u.user_type = 'student'
        GROUP BY u.id, u.name, u.email, u.student_id, u.department
    ''', (student_id,)).fetchone()
    
    conn.close()
    
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    
    return jsonify(dict(student))

@app.route('/api/student_tasks/<int:student_id>')
def api_student_tasks(student_id):
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get tasks for specific student
    tasks = conn.execute('''
        SELECT t.*, ts.id as submission_id, ts.status as submission_status
        FROM tasks t
        LEFT JOIN task_submissions ts ON t.id = ts.task_id AND ts.submitted_by = ?
        WHERE t.assigned_to = ?
        ORDER BY t.due_date DESC
        LIMIT 10
    ''', (student_id, student_id)).fetchall()
    
    conn.close()
    return jsonify([dict(task) for task in tasks])

@app.route('/api/submission_review/<int:submission_id>')
def api_submission_review(submission_id):
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    
    # Get existing review for submission
    review = conn.execute('''
        SELECT feedback, grade FROM task_submissions WHERE id = ?
    ''', (submission_id,)).fetchone()
    
    conn.close()
    
    if review:
        return jsonify(dict(review))
    else:
        return jsonify({'feedback': '', 'grade': ''})

@app.route('/submit_review', methods=['POST'])
def submit_review():
    if 'user_id' not in session or session['user_type'] != 'faculty':
        return jsonify({'error': 'Access denied'}), 403
    
    submission_id = request.form.get('submission_id')
    feedback = request.form.get('feedback', '')
    grade = request.form.get('grade', '')
    
    if not submission_id:
        return jsonify({'error': 'Submission ID required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Update the submission with review
    cursor.execute('''
        UPDATE task_submissions 
        SET feedback = ?, grade = ?
        WHERE id = ?
    ''', (feedback, grade, submission_id))
    
    # If this is a task submission, also update task status to completed if graded
    if grade:
        cursor.execute('''
            UPDATE tasks 
            SET status = 'completed', updated_at = CURRENT_TIMESTAMP
            WHERE id = (SELECT task_id FROM task_submissions WHERE id = ?)
        ''', (submission_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Review submitted successfully!'})

@app.route('/api/users')
def api_users():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, name, email, user_type, student_id, department
        FROM users
        WHERE user_type IN ('student', 'faculty')
        ORDER BY name
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(user) for user in users])

@app.route('/api/tasks')
def api_tasks():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    
    if session['user_type'] == 'admin':
        tasks = conn.execute('''
            SELECT t.*, u.name as assigned_to_name, u.student_id,
                   f.original_filename as task_file_name, f.id as task_file_id
            FROM tasks t
            JOIN users u ON t.assigned_to = u.id
            LEFT JOIN files f ON t.task_file_id = f.id
            WHERE t.assigned_by = ?
            ORDER BY t.created_at DESC
        ''', (session['user_id'],)).fetchall()
    else:
        tasks = conn.execute('''
            SELECT t.*, u.name as assigned_by_name,
                   f.original_filename as task_file_name, f.id as task_file_id,
                   ts.id as submission_id, ts.status as submission_status,
                   sf.original_filename as submission_file_name
            FROM tasks t
            JOIN users u ON t.assigned_by = u.id
            LEFT JOIN files f ON t.task_file_id = f.id
            LEFT JOIN task_submissions ts ON t.id = ts.task_id AND ts.submitted_by = ?
            LEFT JOIN files sf ON ts.file_id = sf.id
            WHERE t.assigned_to = ?
            ORDER BY t.created_at DESC
        ''', (session['user_id'], session['user_id'])).fetchall()
    
    conn.close()
    return jsonify([dict(task) for task in tasks])

@app.route('/api/student_submissions')
def api_student_submissions():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    submissions = conn.execute('''
        SELECT f.*, u.name as uploaded_by_name, u.student_id, u.department,
               ts.task_id, t.title as task_title, ts.submission_text, ts.submitted_at
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        LEFT JOIN task_submissions ts ON f.id = ts.file_id
        LEFT JOIN tasks t ON ts.task_id = t.id
        WHERE u.user_type = 'student' AND f.uploaded_for = 'admin'
        ORDER BY f.upload_date DESC
        LIMIT 10
    ''').fetchall()
    conn.close()
    
    return jsonify([dict(submission) for submission in submissions])

@app.route('/api/files')
def api_files():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    
    if session['user_type'] == 'admin':
        files = conn.execute('''
            SELECT f.*, u.name as uploaded_by_name, u.user_type as uploader_type, u.student_id
            FROM files f
            JOIN users u ON f.uploaded_by = u.id
            WHERE f.uploaded_for != 'task_file'
            ORDER BY f.upload_date DESC
            LIMIT 10
        ''').fetchall()
    else:
        files = conn.execute('''
            SELECT f.*, u.name as uploaded_by_name, u.user_type as uploader_type, u.student_id
            FROM files f
            JOIN users u ON f.uploaded_by = u.id
            WHERE ((u.user_type = 'admin' AND (f.uploaded_for = 'all' OR f.uploaded_for = ?))
               OR f.uploaded_by = ?) AND f.uploaded_for != 'task_file'
            ORDER BY f.upload_date DESC
            LIMIT 10
        ''', (session['user_type'], session['user_id'])).fetchall()
    
    conn.close()
    return jsonify([dict(file) for file in files])

@app.route('/download_task_file/<int:task_id>')
def download_task_file(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get task and associated file
    task = conn.execute('''
        SELECT t.*, f.file_path, f.original_filename
        FROM tasks t
        LEFT JOIN files f ON t.task_file_id = f.id
        WHERE t.id = ? AND (t.assigned_to = ? OR t.assigned_by = ?)
    ''', (task_id, session['user_id'], session['user_id'])).fetchone()
    
    conn.close()
    
    if not task:
        flash('Task not found!', 'error')
        return redirect(url_for('tasks'))
    
    if not task['file_path']:
        flash('No file attached to this task!', 'error')
        return redirect(url_for('tasks'))
    
    try:
        return send_file(task['file_path'], 
                        as_attachment=True, 
                        download_name=task['original_filename'])
    except FileNotFoundError:
        flash('Task file not found on server!', 'error')
        return redirect(url_for('tasks'))

@app.route('/student_submissions')
def student_submissions():
    if 'user_id' not in session or session['user_type'] != 'admin':
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    submissions = conn.execute('''
        SELECT f.*, u.name as uploaded_by_name, u.student_id, u.department, u.email,
               ts.task_id, t.title as task_title, ts.submission_text, ts.submitted_at, ts.feedback, ts.grade
        FROM files f
        JOIN users u ON f.uploaded_by = u.id
        LEFT JOIN task_submissions ts ON f.id = ts.file_id
        LEFT JOIN tasks t ON ts.task_id = t.id
        WHERE u.user_type = 'student' AND f.uploaded_for = 'admin'
        ORDER BY f.upload_date DESC
    ''').fetchall()
    conn.close()
    
    return render_template('student_submissions.html', submissions=submissions)

@app.route('/delete_file/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    if 'user_id' not in session or session['user_type'] != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    conn = get_db_connection()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Delete file from filesystem
        if os.path.exists(file_record['file_path']):
            os.remove(file_record['file_path'])
        
        # Delete from database
        cursor = conn.cursor()
        cursor.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'File deleted successfully'})
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Failed to delete file: {str(e)}'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)