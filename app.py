from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, DateTimeField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

# Create a Flask Instance
app=Flask(__name__)
#Add Database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# initialize database
db = SQLAlchemy(app)
# secret key
app.config['SECRET_KEY'] = "thisisasecretkey"

#Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Create Model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(200))
    trackers = db.relationship('Tracker', backref='track', cascade='all,delete-orphan')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)   

class Tracker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    desc = db.Column(db.String(200))
    type = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    settings = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    logs = db.relationship('Log', backref='logger', cascade='all,delete-orphan')
        
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(150))
    value = db.Column(db.Integer)
    notes = db.Column(db.String(150))
    added_date_time = db.Column(db.DateTime, default=datetime.utcnow)
    tracker_id = db.Column(db.Integer, db.ForeignKey('tracker.id'))

#CReate Login Form
class LoginForm(FlaskForm): 
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()]) 
    submit = SubmitField("Submit")

#Create a Form Class
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords must match!')])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")   

class TrackerForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    desc = StringField("Desc", validators=[DataRequired()], widget=TextArea())
    type = StringField("Type", validators=[DataRequired()])
    settings = StringField("Settings")
    submit = SubmitField("Submit")

class LogForm(FlaskForm):
    timestamp = DateTimeField("Timestamp", validators=[DataRequired()], format = "%d%b%Y %H:%M",default= datetime.utcnow)
    value = StringField("Value", validators=[DataRequired()])
    notes = StringField("Notes", validators=[DataRequired()])
    submit = SubmitField("Submit")

#Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login Successful!")
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong Password- Try Again!") 
        else:
            flash("That user doesn't exist Try Again")         
    return render_template('login.html', form=form)


#Logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out!")
    return redirect(url_for('login'))

#Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


# Create a route decorator
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            #check hash
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name=form.name.data, username=form.username.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.password_hash = ''
        flash("User Added Successfully!") 
    our_users = Users.query.order_by(Users.date_added)       
    return render_template("add_user.html", form=form, name=name, our_users=our_users, user=current_user)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(id):
    id = current_user.id
    user_to_delete = Users.query.fetch(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!")
        our_users = Users.query.order_by(Users.date_added)       
        return render_template("add_user.html", form=form, name=name, our_users=our_users, user=current_user)
    except:
        flash("Error Something went wrong!")
        return render_template("add_user.html", form=form, name=name, our_users=our_users, user=current_user)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html", form=form, name_to_update=name_to_update, user=current_user)
        except:
            flash("Error Looks like there was a problem!")
            return render_template("update.html", form=form, name_to_update=name_to_update, user=current_user)
    else:
        return render_template("update.html", form=form, name_to_update=name_to_update, id=id, user=current_user)


@app.route('/add-tracker', methods=['GET', 'POST'])
@login_required
def add_tracker():
    form = TrackerForm() 
    if form.validate_on_submit():
        track = current_user.id
        tracker = Tracker(title=form.title.data, desc=form.desc.data, type=form.type.data, settings=form.settings.data, user_id=track)
        #Clear the form
        form.title.data = ''
        form.desc.data = ''
        form.type.data = ''
        form.settings.data = ''
        #Add tracker data to db
        db.session.add(tracker)
        db.session.commit()
        flash("Tracker Added Successfully!")
    #Redirect to webpage
    return render_template("add_tracker.html", form=form, user=current_user)

@app.route('/trackers')
@login_required
def trackers():
    trackers = Tracker.query.order_by(Tracker.date_posted)
    return render_template('trackers.html', trackers=trackers, user=current_user)
        
@app.route('/trackers/<int:id>')
@login_required
def tracker(id):
    tracker = Tracker.query.get_or_404(id)
    return render_template('tracker.html', tracker=tracker, user=current_user)

@app.route('/trackers/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_tracker(id):
    tracker = Tracker.query.get_or_404(id)
    form = TrackerForm()
    if form.validate_on_submit():
        tracker.title = form.title.data
        tracker.type = form.type.data
        tracker.settings = form.settings.data
        tracker.desc = form.desc.data
        #Update db
        db.session.add(tracker)
        db.session.commit()
        flash("Tracker has been updated!")
        return redirect(url_for('tracker', id=tracker.id))

    if current_user.id == tracker.user_id:  
        form.title.data = tracker.title
        form.type.data = tracker.type
        form.settings.data = tracker.settings
        form.desc.data = tracker.desc 
        return render_template('edit_tracker.html', form=form, user=current_user)
    else:
        flash("You are not authorized to edit this Tracker")
        trackers = Tracker.query.order_by(Tracker.date_posted)
        return render_template('trackers.html', trackers=trackers, user=current_user)  


@app.route('/trackers/delete/<int:id>')
@login_required
def delete_tracker(id):
    tracker_to_delete = Tracker.query.get_or_404(id)
    id = current_user.id
    if id == tracker_to_delete.track.id:
        try:
            db.session.delete(tracker_to_delete)
            db.session.commit()
            flash("Tracker deleted.")
            #grab all posts from the db
            trackers = Tracker.query.order_by(Tracker.date_posted)
            return render_template('trackers.html', trackers=trackers, user=current_user)
        except:
            #return error msg
            flash("error deleting Tracker")
            trackers = Tracker.query.order_by(Tracker.date_posted)
            return render_template('trackers.html', trackers=trackers, user=current_user)
    else: 
        flash("You are not authorized to delete that tracker.")
            #grab all posts from the db
        trackers = Tracker.query.order_by(Tracker.date_posted)
        return render_template('trackers.html', trackers=trackers, user=current_user)       

@app.route('/trackers/add-logs', methods=['GET', 'POST'])
@login_required
def add_logs():
    form = LogForm() 
    if form.validate_on_submit():
        logger = current_user.id
        log = Log(timestamp=form.timestamp.data, value=form.value.data, notes=form.notes.data, tracker_id = logger)
        #Clear the form
        form.timestamp.data = ''
        form.value.data = ''
        form.notes.data = ''
        #Add post data to db
        db.session.add(log)
        db.session.commit()
        flash("Log Added Successfully!")
    #Redirect to webpage
    return render_template("add_logs.html", form=form)

@app.route('/trackers/logs/<int:id>')
@login_required
def logs(id): #this id belongs to tracker
    logs = Log.query.order_by(Log.added_date_time)
    this_log = Log.query.get_or_404(id)
    tracker = Tracker.query.get(this_log.tracker_id)
    return render_template('logs.html', logs=logs, tracker=tracker, user=current_user)
        
@app.route('/trackers/log/<int:id>')
@login_required
def log(id): #this id belongs to log
    log = Log.query.get_or_404(id)
    return render_template('log.html', log=log, user=current_user)

@app.route('/trackers/logs/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_log(id):
    log = Log.query.get_or_404(id)
    tracker = Tracker.query.get(log.tracker_id)
    form = LogForm()
    if form.validate_on_submit():
        log.timestamp = form.timestamp.data
        log.value = form.value.data
        log.notes = form.notes.data
        #Update db
        db.session.add(log)
        db.session.commit()
        flash("Log has been updated!")
        return redirect(url_for('log', id=log.id))
    if current_user.id == tracker.user_id and log.tracker_id == tracker.id:  
        form.timestamp.data = log.timestamp
        form.value.data = log.value
        form.notes.data = log.notes
        return render_template('edit_log.html', form=form, user=current_user)
    else:
        flash("You are not authorized to edit this Log")
        logs = Log.query.order_by(Log.added_date_time)
        return render_template('logs.html', logs=logs, user=current_user)


@app.route('/trackers/logs/delete/<int:id>')
@login_required
def delete_log(id):
    log_to_delete = Log.query.get_or_404(id)
    id = current_user.id
    if id == log_to_delete.logger.id:
        try:
            db.session.delete(log_to_delete)
            db.session.commit()
            flash("Log deleted.")
            #grab all posts from the db
            logs = Log.query.order_by(Log.added_date_time)
            return render_template('logs.html', logs=logs, user=current_user)
        except:
            #return error msg
            flash("error deleting Log")
            logs = Log.query.order_by(Log.added_date_time)
            return render_template('logs.html', logs=logs, user=current_user)
    else: 
        flash("You are not authorized to delete that Log.")
            #grab all posts from the db
        logs = Log.query.order_by(Log.added_date_time)
        return render_template('logs.html', logs=logs, user=current_user) 

@app.route('/summary/<int:id>', methods=['GET', 'POST'])
@login_required
def view_summary(id):
    tracker = Tracker.query.get(id)
    id = current_user.id
    logs = Log.query.all()
    if current_user.id == tracker.user_id:
        try:
            import sqlite3
            con = sqlite3.connect(r"E:\New folder\database.db")
            print("Database opened successfully")
            c = con.cursor()
            c.execute('SELECT timestamp, value FROM Log WHERE tracker_id={}'.format(tracker.id))

            data = c.fetchall()
            dates = []
            values = []
            import matplotlib.pyplot as plt
            from matplotlib import style
            style.use('fivethirtyeight')
            from dateutil import parser

            for row in data:
                dates.append(parser.parse(row[0]))
                values.append(row[1])

            fig = plt.figure(figsize=(18, 8))
            plt.plot_date(dates, values, '-')
            plt.xlabel('Date and Time')
            plt.ylabel('Values')
            plt.tight_layout()
            plt.savefig(r"E:\New folder\static\Images\graph.png")
            # plt.show()

            gon = sqlite3.connect(r"E:\New folder\database.db")
            g = gon.cursor()
            added_date_time = g.execute('SELECT added_date_time FROM Log WHERE id=(SELECT max(id) FROM Log WHERE tracker_id={})'.format(id))

            added_date_time = added_date_time.fetchone()
            added_date_time = ''.join(added_date_time)
            print(added_date_time)
            return render_template("view_graph.html", user=current_user, tracker=tracker, logs=logs)
        except Exception as e:
            print(e)
            flash('Something went wrong.', category='error')
            return render_template("view_graph.html", user=current_user, tracker=tracker, logs=logs)


@app.route('/')
def index():
    return render_template("index.html")


#Custom Error page
#invalid url
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html")

#internal server error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html")  


# Run app
if __name__=="__main__":
    app.run(debug=True)    