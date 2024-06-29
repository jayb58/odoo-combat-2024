# app/routes.py

from flask import render_template, url_for, flash, redirect, abort, request
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, WorkoutPlanForm, DietPlanForm
from app.models import User, WorkoutPlan, DietPlan
from flask_login import login_user, current_user, logout_user, login_required
from functools import wraps

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')

@app.route("/admin")
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin.html', title='Admin Dashboard')

@app.route("/trainer")
@login_required
@role_required('trainer')
def trainer_dashboard():
    workout_form = WorkoutPlanForm()
    diet_form = DietPlanForm()
    return render_template('trainer.html', title='Trainer Dashboard', workout_form=workout_form, diet_form=diet_form)

@app.route("/trainer/workout/new", methods=['POST'])
@login_required
@role_required('trainer')
def new_workout():
    form = WorkoutPlanForm()
    if form.validate_on_submit():
        workout_plan = WorkoutPlan(name=form.name.data, description=form.description.data, difficulty=form.difficulty.data, trainer_id=current_user.id)
        db.session.add(workout_plan)
        db.session.commit()
        flash('Your workout plan has been created!', 'success')
        return redirect(url_for('trainer_dashboard'))
    return render_template('create_workout.html', title='New Workout Plan', form=form)

@app.route("/trainer/diet/new", methods=['POST'])
@login_required
@role_required('trainer')
def new_diet():
    form = DietPlanForm()
    if form.validate_on_submit():
        diet_plan = DietPlan(name=form.name.data, description=form.description.data, trainer_id=current_user.id)
        db.session.add(diet_plan)
        db.session.commit()
        flash('Your diet plan has been created!', 'success')
        return redirect(url_for('trainer_dashboard'))
    return render_template('create_diet.html', title='New Diet Plan', form=form)

@app.route("/workouts")
@login_required
def workouts():
    workouts = WorkoutPlan.query.all()
    return render_template('workouts.html', title='Workouts', workouts=workouts)

@app.route("/diets")
@login_required
def diets():
    diets = DietPlan.query.all()
    return render_template('diets.html', title='Diet Plans', diets=diets)
