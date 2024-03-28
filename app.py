from flask import (
    Flask,
    render_template,
    session,
    redirect,
    request,
)
from requests import post
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo import MongoClient

connection_string = "mongodb+srv://mihaiciorobitca:UtIekdcPUmWXB9rC@cluster.o1rs5cw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster"

app = Flask(__name__)

app.secret_key = "really-secret-key" 

mongo = MongoClient(connection_string)
db = mongo.databasesto

@app.route('/')
def index():
    products = db.products.find()
    return render_template("index.html", products=products)

"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Users.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user"] = username
            return render_template("login.html", success="Login successfuly")
        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        confirm_password = request.form['confirmPassword']
        if Users.query.filter_by(username=username).first() or Users.query.filter_by(email=email).first():
            return render_template("register.html", error="Username or email already exists")
        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match")
        recaptcha = request.form["g-recaptcha-response"]
        if recaptcha:
            private_key = "6LdD26QpAAAAADz68_QLJKq7ctwYXb6IAZTiXFaL"
            response = post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': private_key,
                    'response': recaptcha
                }
            )
            result = response.json()
            if result['success']:
                new_user = Users(username=username, password=generate_password_hash(password), email=email)
                db.session.add(new_user)
                db.session.commit()
                return render_template("register.html", success="User registered")
        return render_template("register.html", error="reCAPTCHA verification failed.")
    return render_template("register.html")
 """

@app.route('/admin')
def admin():
    if session.get("admin", False):
        return render_template("admin.html")
    return redirect("/login")

@app.route('/about')
def about():
    return render_template("about.html")

"""
@app.route('/cart')
def cart():
    if session.get("user", False):
        user_username = session.get("user")
        carts = Cart.query.filter_by(user_username=user_username).all()
        products = []
        for cart in carts:
            user_product = Products.query.filter_by(name=cart.product_name).first()
            products.append((user_product, cart.quantity, round(user_product.price * cart.quantity, 2)))
        return render_template("cart.html", username=session.get("user", False), products=products)
    return redirect("/login")

@app.route('/add-cart', methods=["POST"])
def add_cart():
    if session.get("user", False):
        user_username = session.get("user")
        product_name = request.form['product_name']
        cart = Cart.query.filter_by(user_username=user_username, product_name=product_name).first()
        if cart:
            cart.quantity += 1
        else:
            new_cart = Cart(user_username=user_username, product_name=product_name)
            db.session.add(new_cart)
        db.session.commit()
        return redirect("/")
    return redirect("/login")

@app.route('/increase-cart', methods=["POST"])
def increase_cart():
    user_username = session.get("user")
    product_name = request.form['product_name']
    cart = Cart.query.filter_by(user_username=user_username, product_name=product_name).first()
    if cart.quantity > 0:
        cart.quantity += 1
    db.session.commit()
    return redirect("/cart")

@app.route('/decrease-cart', methods=["POST"])
def decrease_cart():
    user_username = session.get("user")
    product_name = request.form['product_name']
    cart = Cart.query.filter_by(user_username=user_username, product_name=product_name).first()
    if cart.quantity > 0:
        cart.quantity -= 1
    db.session.commit()
    return redirect("/cart")

@app.route('/remove-cart', methods=["POST"])
def remove_cart():
    user_username = session.get("user")
    product_name = request.form['product_name']
    cart = Cart.query.filter_by(user_username=user_username, product_name=product_name).first()
    db.session.delete(cart)
    db.session.commit()
    return redirect("/cart")
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")


