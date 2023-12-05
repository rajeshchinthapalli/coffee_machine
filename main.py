from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy()
db.init_app(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Coffee(db.Model):
    id = db.Column(db.INTEGER, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    milk = db.Column(db.INTEGER, nullable=False)
    coffee = db.Column(db.INTEGER, nullable=False)
    water = db.Column(db.INTEGER, nullable=False)
    amount = db.Column(db.INTEGER, nullable=False)


class Resources(db.Model):
    id = db.Column(db.INTEGER, primary_key=True)
    milk = db.Column(db.INTEGER, nullable=False)
    coffee = db.Column(db.INTEGER, nullable=False)
    water = db.Column(db.INTEGER, nullable=False)
    money = db.Column(db.INTEGER, nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('welcome'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
            return render_template("login.html")
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template("register.html")

        if password == confirm_password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)

            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/welcome')
@login_required
def welcome():
    return render_template("welcome.html", name=current_user.username)

@app.route("/coffee", methods=['GET', 'POST'])
@login_required
def coffee():
    if request.method == 'POST':
        coffee = request.form.get('coffee_type')

        if coffee == 'Espresso':
            return redirect(url_for('Espresso'))
        elif coffee == 'Cappuccino':
            return redirect(url_for('Cappuccino'))
        elif coffee == 'Latte':
            return redirect(url_for("Latte"))
    return render_template("welcome.html")



@app.route("/payment", methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        coffee_name = session.get('coffee_name')
        quarter = request.form.get('quarters')
        dime = request.form.get('dimes')
        nickel = request.form.get('nickels')
        penny = request.form.get('pennies')

        # Check if any of the coin values are None before converting to int
        if quarter is not None and dime is not None and nickel is not None and penny is not None:
            try:
                total_amount_inserted = (int(quarter) * 0.25) + (int(dime) * 0.01) + (int(nickel) * 0.1) + (int(penny) * 0.05)
            except ValueError:
                flash('Invalid coin values. Please enter valid numbers.', 'danger')
                return render_template("payment.html")

            coffee = Coffee.query.filter_by(name=coffee_name).first()
            change = 0

            if total_amount_inserted > coffee.amount:
                change = total_amount_inserted - coffee.amount
                change = round(change, 2)
            elif total_amount_inserted < coffee.amount:
                short = coffee.amount - total_amount_inserted
                session["short"] = short
                return redirect(url_for("fail"))

            if update_resources(coffee_name):
                session['change'] = change
                session['name'] = coffee_name
                return redirect(url_for("success"))
        else:
            flash('Please provide valid coin values.', 'danger')

    return render_template("payment.html")


@app.route("/failure")
def fail():
    short = session.get("short")
    coffee = session.get("coffee_name")
    return render_template("fail.html", short=short, coffee=coffee)

@app.route("/espresso")
@login_required
def Espresso():
    coffee_name = 'Espresso'
    if resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("nostock.html")

@app.route("/latte")
@login_required
def Latte():
    coffee_name = 'Latte'
    if resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("nostock.html")

@app.route("/cappuccino")
@login_required
def Cappuccino():
    coffee_name = 'Cappuccino'
    if resources(coffee_name):
        session['coffee_name'] = coffee_name
        return redirect(url_for("payment"))
    else:
        return render_template("nostock.html")

def resources(coffee_name):
    res = db.session.query(Coffee).filter_by(name=coffee_name).first()
    print(res)
    if res:
        available_resources = db.session.query(Resources).first()

        if (
                available_resources.milk >= res.milk and
                available_resources.coffee >= res.coffee and
                available_resources.water >= res.water
        ):
            return True
        else:
            return False

def update_resources(coffee_name):
    coffee = Coffee.query.filter_by(name=coffee_name).first()
    resources = Resources.query.first()
    if coffee and resources:
        if resources.milk > 0 and resources.water > 0 and resources.coffee > 0:
            resources.milk -= coffee.milk
            resources.coffee -= coffee.coffee
            resources.water -= coffee.water
            resources.money += coffee.amount
            db.session.commit()
            return True

@app.route("/pass")
def report():
    password = request.args.get('pass')
    if password == 'report':
        resources = Resources.query.first()
        amount = resources.money
        milk = resources.milk
        water = resources.water
        coffee = resources.coffee
        return render_template("report.html", coffee=coffee, water=water, amount=amount, milk=milk)

@app.route("/success")
@login_required
def success():
    coffee_name = session.get('name')
    # time.sleep(3)
    change = session.get('change')
    if change == 0:
        balance = False
    else:
        balance = True
    return render_template('success.html', coffeename=coffee_name, change=change, user=current_user.username,
                           balance=balance)

@app.route("/addcoffee")
def addvalues():
    coffeename = request.args.get('name')
    milk = request.args.get('milk')
    water = request.args.get('water')
    coffee_powder = request.args.get('coffee')
    amount = request.args.get('amount')
    coffee_instance = Coffee(coffee_name=coffeename, milk_required_ml=milk, water_required_ml=water,
                             coffee_require_ml=coffee_powder,
                             amount=amount)
    db.session.add(coffee_instance)
    db.session.commit()
    return "added"


@app.route("/add_resource")
def addresource():
    milk = request.args.get('milk')
    water = request.args.get('water')
    coffee_powder = request.args.get('coffee')
    amount = request.args.get('amount')
    coffee_instance = Resources(milk_stock=milk, water_stock=water, coffee_powder_stock=coffee_powder,
                                wallet=amount)
    db.session.add(coffee_instance)
    db.session.commit()
    return "added"

if __name__ == "__main__":
    app.run(debug=True)


