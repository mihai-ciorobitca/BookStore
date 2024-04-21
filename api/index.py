from oauthlib.oauth2 import WebApplicationClient
from flask import Flask, render_template, session, redirect, request, jsonify, url_for
from requests import post
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo import MongoClient
from dotenv import load_dotenv
from os import getenv
from bson import ObjectId
from requests import get, post
from json import dumps

load_dotenv()

MONGO_URI = getenv("MONGO_URI")
PRIVATE_KEY = getenv("PRIVATE_KEY")
SECRET_KEY = getenv("SECRET_KEY")
GOOGLE_CLIENT_ID = getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(GOOGLE_CLIENT_ID)

app = Flask(__name__)

app.secret_key = SECRET_KEY

mongo = MongoClient(MONGO_URI)
db = mongo.database


@app.route("/")
def index():
    products = db.products.find()
    success = None
    error = None
    if "success" in session:
        success = session.pop("success")
    if "error" in session:
        error = session.pop("error")
    return render_template(
        "index.html",
        products=products,
        success=success,
        error=error,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "admin":
            session["admin"] = True
            return jsonify({"status": "success", "route": "/admin"})

        user = db.users.find_one({"username": username})
        if not user or not check_password_hash(user["password"], password):
            return jsonify(
                {"status": "fail", "message": "Incorect username or password"}
            )

        session["user"] = username
        session["success"] = "Successfully logged in"
        return jsonify({"status": "success", "route": "/"})
    return render_template("login.html")


@app.route("/google/login")
def google_login():
    google_provider_cfg = get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/google/login/callback")
def google_callback():
    code = request.args.get("code")
    google_provider_cfg = get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    redirect_uri = url_for("google_callback", _external=True)

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=redirect_uri,
        code=code,
    )
    token_response = post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        email = userinfo_response.json()["email"]
        user = db.users.find_one({"email": email})
        if user:
            session["user"] = user["username"]
            session["success"] = "Successfully logged in"
            return jsonify({"status": "success", "route": "/"})
        return redirect("/login")

    return "User email not available or not verified by Google.", 400


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        confirm_password = request.form["confirmPassword"]

        if db.users.find_one({"username": username}):
            return jsonify({"status": "fail", "message": "Username already exists"})
        if db.users.find_one({"email": email}):
            return jsonify({"status": "fail", "message": "Email already registered"})
        if password != confirm_password:
            return jsonify({"status": "fail", "message": "Passwords do not match"})

        recaptcha = request.form["g-recaptcha-response"]
        if recaptcha:
            response = post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": PRIVATE_KEY, "response": recaptcha},
            )
            result = response.json()
            if result["success"]:
                hashed_password = generate_password_hash(password)
                db.users.insert_one(
                    {"username": username, "password": hashed_password, "email": email}
                )
                return jsonify(
                    {
                        "status": "success",
                        "message": "Successfully created account! You can now log in",
                    }
                )
            return jsonify(
                {"status": "fail", "message": "reCAPTCHA verification failed."}
            )
        return jsonify({"status": "fail", "message": "reCAPTCHA verification problem."})
    return render_template("register.html")


@app.route("/admin")
def admin():
    if session.get("admin", False):
        return render_template("admin.html")
    return redirect("/login")


@app.route("/admin/users")
def manage_users():
    if session.get("admin", False):
        users = db.users.find()
        return render_template("manage_users.html", users=users)
    return redirect("/login")


@app.route("/admin/users/delete/<user_id>")
def delete_user(user_id):
    if session.get("admin", False):
        db.users.delete_one({"_id": ObjectId(user_id)})
        return redirect("/admin/users")
    return redirect("/login")


@app.route("/admin/users/change_password/<user_id>", methods=["POST"])
def change_password(user_id):
    if session.get("admin", False):
        new_password = request.form.get("new_password")
        db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password": generate_password_hash(new_password)}},
        )
        return redirect("/admin/users")
    return redirect("/login")


@app.route("/admin/products")
def manage_products():
    if session.get("admin", False):
        products = db.products.find()
        return render_template("manage_products.html", products=products)
    return redirect("/login")


@app.route("/admin/products/update/<product_id>", methods=["POST"])
def update_product(product_id):
    if session.get("admin", False):
        name = request.form.get("name")
        price = request.form.get("price")
        stock = request.form.get("stock")
        db.products.update_one(
            {"_id": ObjectId(product_id)},
            {"$set": {"name": name, "price": price, "stock": stock}},
        )
        return redirect("/admin/products")
    return redirect("/login")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/cart")
def cart():
    if session.get("user", False):
        username = session.get("user")
        cart = db.users.find_one({"username": username})
        if cart:
            products = cart.get("cart", [])
        else:
            products = []
        return render_template(
            "cart.html", username=session.get("user", False), products=products
        )
    return redirect("/login")


@app.route("/cart/add-cart", methods=["POST"])
def add_cart():
    if session.get("user", False):
        username = session.get("user")
        product_name = request.form["product_name"]
        existing_product = db.users.find_one(
            {"username": username, "cart.name": product_name}
        )
        if existing_product:
            db.users.update_one(
                {"username": username, "cart.name": product_name},
                {"$inc": {"cart.$.quantity": 1}},
            )
        else:
            db.users.update_one(
                {"username": username},
                {"$push": {"cart": {"name": product_name, "quantity": 1}}},
                upsert=True,
            )
        return jsonify(
            {
                "status": "success",
                "message": "Product added successfully",
                "route": "/cart",
            }
        )
    return jsonify({"status": "error", "message": "User not logged in"})


@app.route("/cart/increase-cart", methods=["POST"])
def increase_cart():
    username = session.get("user")
    product_name = request.form["product_name"]
    db.users.update_one(
        {"username": username, "cart.name": product_name},
        {"$inc": {"cart.$.quantity": 1}},
    )
    return jsonify(
        {
            "status": "success",
            "message": "Quantity increased successfully",
            "route": "/cart",
        }
    )


@app.route("/cart/decrease-cart", methods=["POST"])
def decrease_cart():
    username = session.get("user")
    product_name = request.form["product_name"]
    user = db.users.find_one({"username": username, "cart.name": product_name})
    if user:
        cart_item = next(item for item in user["cart"] if item["name"] == product_name)
        if cart_item["quantity"] == 1:
            return jsonify(
                {
                    "status": "success",
                    "message": "Quantity decreased successfully",
                    "route": "/cart",
                }
            )
    db.users.update_one(
        {"username": username, "cart.name": product_name},
        {"$inc": {"cart.$.quantity": -1}},
    )
    return jsonify(
        {
            "status": "success",
            "message": "Quantity decreased successfully",
            "route": "/cart",
        }
    )


@app.route("/cart/remove-cart", methods=["POST"])
def remove_cart():
    username = session.get("user")
    product_name = request.form["product_name"]
    db.users.update_one(
        {"username": username}, {"$pull": {"cart": {"name": product_name}}}
    )
    return jsonify(
        {
            "status": "success",
            "message": "Product removed successfully",
            "route": "/cart",
        }
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
