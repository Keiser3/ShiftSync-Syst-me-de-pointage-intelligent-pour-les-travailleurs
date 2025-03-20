from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from datetime import datetime
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///time_tracking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
jwt = JWTManager(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
CORS(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    time = db.Column(db.DateTime, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        login_user(user)
        access_token = create_access_token(identity=username)
        return redirect(url_for('index'))
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user')
@jwt_required()
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/admin')
@jwt_required()
def admin_dashboard():
    return render_template('admin_dashboard.html')







app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///time_tracking.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
jwt = JWTManager(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    log_type = db.Column(db.String(20), nullable=False)
    time = db.Column(db.DateTime, nullable=False)

def role_required(role):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.filter_by(username=user_id).first()
            if user and user.role == role:
                return f(*args, **kwargs)
            return jsonify({'message': 'Access denied'}), 403
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    role = request.json.get('role', 'user')  # Default role is 'user'
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    new_user = User(username=username, password=password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/clock-in', methods=['POST'])
@jwt_required()
def clock_in():
    user_id = get_jwt_identity()
    user = User.query.filter_by(username=user_id).first()
    time = datetime.now()
    new_log = TimeLog(user_id=user.id, log_type='clock-in', time=time)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'Clock-in successful', 'time': time}), 200

@app.route('/clock-out', methods=['POST'])
@jwt_required()
def clock_out():
    user_id = get_jwt_identity()
    user = User.query.filter_by(username=user_id).first()
    time = datetime.now()
    new_log = TimeLog(user_id=user.id, log_type='clock-out', time=time)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': 'Clock-out successful', 'time': time}), 200

@app.route('/break', methods=['POST'])
@jwt_required()
def break_time():
    user_id = get_jwt_identity()
    user = User.query.filter_by(username=user_id).first()
    break_type = request.json['break_type']  # 'start' or 'end'
    time = datetime.now()
    new_log = TimeLog(user_id=user.id, log_type=f'break-{break_type}', time=time)
    db.session.add(new_log)
    db.session.commit()
    return jsonify({'message': f'Break {break_type} successful', 'time': time}), 200

@app.route('/overtime', methods=['GET'])
@jwt_required()
def calculate_overtime():
    user_id = get_jwt_identity()
    user = User.query.filter_by(username=user_id).first()
    logs = TimeLog.query.filter_by(user_id=user.id).all()
    total_hours = sum([log.time.hour for log in logs if log.log_type == 'clock-out']) - sum([log.time.hour for log in logs if log.log_type == 'clock-in'])
    overtime_hours = max(0, total_hours - 8)  # Assuming 8-hour workday
    return jsonify({'overtime_hours': overtime_hours}), 200


@app.route('/admin/reports', methods=['GET'])
@role_required('admin')
def admin_reports():
    reports = []
    users = User.query.all()
    for user in users:
        user_logs = TimeLog.query.filter_by(user_id=user.id).all()
        clock_ins = [log.time for log in user_logs if log.log_type == 'clock-in']
        clock_outs = [log.time for log in user_logs if log.log_type == 'clock-out']
        break_starts = [log.time for log in user_logs if log.log_type == 'break-start']
        break_ends = [log.time for log in user_logs if log.log_type == 'break-end']

        total_work_hours = calculate_total_work_hours(clock_ins, clock_outs)
        average_work_hours = calculate_average_work_hours(clock_ins, clock_outs)
        total_break_duration = calculate_total_break_duration(break_starts, break_ends)
        overtime_hours = calculate_user_overtime(user.id)

        report = {
            'username': user.username,
            'total_work_hours': total_work_hours,
            'average_work_hours': average_work_hours,
            'total_break_duration': total_break_duration,
            'overtime_hours': overtime_hours,
            'clock_ins': clock_ins,
            'clock_outs': clock_outs,
            'breaks': {
                'start': break_starts,
                'end': break_ends
            }
        }
        reports.append(report)
    return jsonify(reports), 200


def calculate_total_work_hours(clock_ins, clock_outs):
    total_hours = sum((out - inp).total_seconds() / 3600 for inp, out in zip(clock_ins, clock_outs))
    return total_hours


def calculate_average_work_hours(clock_ins, clock_outs):
    total_days = len(set(log.date() for log in clock_ins))
    total_hours = calculate_total_work_hours(clock_ins, clock_outs)
    return total_hours / total_days if total_days > 0 else 0


def calculate_total_break_duration(break_starts, break_ends):
    total_break_seconds = sum((end - start).total_seconds() for start, end in zip(break_starts, break_ends))
    return total_break_seconds / 3600  # Convert to hours


def calculate_user_overtime(user_id):
    logs = TimeLog.query.filter_by(user_id=user_id).all()
    total_hours = sum([log.time.hour for log in logs if log.log_type == 'clock-out']) - sum(
        [log.time.hour for log in logs if log.log_type == 'clock-in'])
    overtime_hours = max(0, total_hours - 8)  # Assuming 8-hour workday
    return overtime_hours

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)