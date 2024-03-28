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
from os import environ
from dotenv import load_dotenv 

mongo_uri = environ.get('MONGO_URI')  
print(mongo_uri)

app = Flask(__name__)

app.secret_key = "really-secret-key"

mongo = MongoClient(mongo_uri)
db = mongo.database


@app.route("/")
def index():
    products = db.products.find()
    return render_template("index.html", products=products)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = db.users.find_one({"username": username})

        if not user:
            return render_template("login.html", error="User does not exist.")
        elif not check_password_hash(user["password"], password):
            return render_template("login.html", "Incorrect password.")
        session["user"] = username
        return render_template("login.html", success="Login successfuly")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        confirm_password = request.form["confirmPassword"]
        if db.users.find_one({"username": username}):
            return render_template("register.html", error="Username already exists")
        if db.users.find_one({"email": email}):
            return render_template("register.html", error="Email already registered")
        if password != confirm_password:
            return render_template("register.html", error="Password do not match")
        recaptcha = request.form["g-recaptcha-response"]
        if recaptcha:
            private_key = "6LdD26QpAAAAADz68_QLJKq7ctwYXb6IAZTiXFaL"
            response = post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": private_key, "response": recaptcha},
            )
            result = response.json()
            if result["success"]:
                hashed_password = generate_password_hash(password)
                db.users.insert_one(
                    {"username": username, "password": hashed_password, "email": email}
                )
                return render_template(
                    "register.html",
                    success="Successfully created account! You can now log in",
                )
            return render_template(
                "register.html", error="reCAPTCHA verification failed."
            )
        return render_template("register.html", error="reCAPTCHA verification problem.")
    return render_template("register.html")


@app.route("/admin")
def admin():
    if session.get("admin", False):
        return render_template("admin.html")
    return redirect("/login")


@app.route("/about")
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
