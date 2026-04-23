from flask import Flask, request, jsonify
import os
import bcrypt
import pymysql
import requests
import datetime
import base64
from requests.auth import HTTPBasicAuth
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["UPLOAD_FOLDER"] = "static/images"

# ── DB CONNECTION ──────────────────────────────────────────────
def get_db():
    return pymysql.connect(
        host="mysql-maloba.alwaysdata.net",
        user="maloba",
        password="modcom1234",
        database="maloba_acoustiq",
        cursorclass=pymysql.cursors.DictCursor
    )


# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════

# ── SIGNUP ────────────────────────────────────────────────────
@app.route("/api/signup", methods=["POST"])
def signup():
    first_name = request.form.get("first_name", "").strip()
    last_name  = request.form.get("last_name",  "").strip()
    email      = request.form.get("email",      "").strip()
    phone      = request.form.get("phone",      "").strip()
    password   = request.form.get("password",   "").strip()

    if not first_name or not last_name or not email or not phone or not password:
        return jsonify({"message": "All fields are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    # Check for duplicate email or phone
    cursor.execute(
        "SELECT user_id FROM users WHERE email = %s OR phone = %s",
        (email, phone)
    )
    if cursor.fetchone():
        connection.close()
        return jsonify({"message": "An account with that email or phone number already exists."}), 409

    # Hash the password
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO users (first_name, last_name, email, phone, password) VALUES (%s, %s, %s, %s, %s)",
        (first_name, last_name, email, phone, hashed.decode("utf-8"))
    )
    connection.commit()
    connection.close()
    return jsonify({"message": "Account created successfully!"}), 201


# ── SIGNIN ────────────────────────────────────────────────────
@app.route("/api/signin", methods=["POST"])
def signin():
    email    = request.form.get("email",    "").strip()
    password = request.form.get("password", "").strip()

    if not email or not password:
        return jsonify({"message": "Email and password are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    connection.close()

    if not user:
        return jsonify({"message": "Login failed. Check your credentials and try again."}), 401

    # Verify hashed password
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"].encode("utf-8")):
        return jsonify({"message": "Login failed. Check your credentials and try again."}), 401

    # Don't send the password hash back to the frontend
    user.pop("password", None)
    return jsonify({"message": "Login successful!", "user": user}), 200


# ══════════════════════════════════════════════════════════════
#  PROFILE
# ══════════════════════════════════════════════════════════════

# ── UPDATE PROFILE DETAILS ────────────────────────────────────
@app.route("/api/profile/update", methods=["PUT"])
def update_profile():
    user_id    = request.form.get("user_id")
    first_name = request.form.get("first_name", "").strip()
    last_name  = request.form.get("last_name",  "").strip()
    email      = request.form.get("email",      "").strip()
    phone      = request.form.get("phone",      "").strip()

    if not all([user_id, first_name, last_name, email, phone]):
        return jsonify({"message": "All fields are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    # Make sure updated email/phone don't belong to a different user
    cursor.execute(
        "SELECT user_id FROM users WHERE (email = %s OR phone = %s) AND user_id != %s",
        (email, phone, user_id)
    )
    if cursor.fetchone():
        connection.close()
        return jsonify({"message": "That email or phone number is already in use by another account."}), 409

    cursor.execute(
        "UPDATE users SET first_name=%s, last_name=%s, email=%s, phone=%s WHERE user_id=%s",
        (first_name, last_name, email, phone, user_id)
    )
    connection.commit()
    connection.close()
    return jsonify({"message": "Profile updated successfully!"}), 200


# ── CHANGE PASSWORD ───────────────────────────────────────────
@app.route("/api/profile/password", methods=["PUT"])
def change_password():
    user_id      = request.form.get("user_id")
    old_password = request.form.get("old_password", "").strip()
    new_password = request.form.get("new_password", "").strip()

    if not all([user_id, old_password, new_password]):
        return jsonify({"message": "All fields are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("SELECT password FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()

    if not user:
        connection.close()
        return jsonify({"message": "User not found."}), 404

    if not bcrypt.checkpw(old_password.encode("utf-8"), user["password"].encode("utf-8")):
        connection.close()
        return jsonify({"message": "Current password is incorrect."}), 401

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    cursor.execute(
        "UPDATE users SET password=%s WHERE user_id=%s",
        (hashed.decode("utf-8"), user_id)
    )
    connection.commit()
    connection.close()
    return jsonify({"message": "Password changed successfully!"}), 200


# ── DELETE ACCOUNT ────────────────────────────────────────────
@app.route("/api/profile/delete/<int:user_id>", methods=["DELETE"])
def delete_account(user_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    connection.commit()
    connection.close()
    return jsonify({"message": "Account deleted successfully."}), 200


# ══════════════════════════════════════════════════════════════
#  PRODUCTS
# ══════════════════════════════════════════════════════════════

# ── GET PRODUCTS (with filtering) ─────────────────────────────
@app.route("/api/products", methods=["GET"])
def get_products():
    category         = request.args.get("category")
    brand            = request.args.get("brand")
    instrument_type  = request.args.get("instrument_type")
    genre            = request.args.get("genre")
    level            = request.args.get("level")
    condition_status = request.args.get("condition_status")
    format_type      = request.args.get("format")
    price_min        = request.args.get("price_min")
    price_max        = request.args.get("price_max")
    search           = request.args.get("search")

    sql    = """
        SELECT p.*,
               ROUND(AVG(r.stars), 1) AS avg_rating,
               COUNT(r.rating_id)     AS rating_count
        FROM products p
        LEFT JOIN ratings r ON p.product_id = r.product_id
        WHERE 1=1
    """
    params = []

    if category:
        sql += " AND p.category = %s"
        params.append(category)
    if brand:
        sql += " AND p.brand = %s"
        params.append(brand)
    if instrument_type:
        sql += " AND p.instrument_type = %s"
        params.append(instrument_type)
    if genre:
        sql += " AND p.genre = %s"
        params.append(genre)
    if level:
        sql += " AND p.level = %s"
        params.append(level)
    if condition_status:
        sql += " AND p.condition_status = %s"
        params.append(condition_status)
    if format_type:
        sql += " AND p.format = %s"
        params.append(format_type)
    if price_min:
        sql += " AND p.product_cost >= %s"
        params.append(price_min)
    if price_max:
        sql += " AND p.product_cost <= %s"
        params.append(price_max)
    if search:
        sql += " AND (p.product_name LIKE %s OR p.product_description LIKE %s)"
        params.append(f"%{search}%")
        params.append(f"%{search}%")

    sql += " GROUP BY p.product_id ORDER BY p.created_at DESC"

    connection = get_db()
    cursor = connection.cursor()
    cursor.execute(sql, params)
    products = cursor.fetchall()
    connection.close()
    return jsonify(products), 200


# ── GET SINGLE PRODUCT ────────────────────────────────────────
@app.route("/api/product/<int:product_id>", methods=["GET"])
def get_product(product_id):
    connection = get_db()
    cursor = connection.cursor()

    # Main product + avg rating
    cursor.execute("""
        SELECT p.*,
               ROUND(AVG(r.stars), 1) AS avg_rating,
               COUNT(r.rating_id)     AS rating_count
        FROM products p
        LEFT JOIN ratings r ON p.product_id = r.product_id
        WHERE p.product_id = %s
        GROUP BY p.product_id
    """, (product_id,))
    product = cursor.fetchone()

    if not product:
        connection.close()
        return jsonify({"message": "Product not found."}), 404

    # Extra images
    cursor.execute(
        "SELECT image_name FROM product_images WHERE product_id = %s",
        (product_id,)
    )
    product["extra_images"] = cursor.fetchall()

    # Related products (same category, excluding this product)
    cursor.execute("""
        SELECT p.product_id, p.product_name, p.product_photo, p.product_cost,
               ROUND(AVG(r.stars), 1) AS avg_rating
        FROM products p
        LEFT JOIN ratings r ON p.product_id = r.product_id
        WHERE p.category = %s AND p.product_id != %s
        GROUP BY p.product_id, p.product_name, p.product_photo, p.product_cost
        ORDER BY RAND()
        LIMIT 4
    """, (product["category"], product_id))
    product["related"] = cursor.fetchall()

    connection.close()
    return jsonify(product), 200


# ── ADD PRODUCT (auth-gated) ──────────────────────────────────
@app.route("/api/add_product", methods=["POST"])
def add_product():
    user_id         = request.form.get("user_id")
    product_name    = request.form.get("product_name",    "").strip()
    product_description = request.form.get("product_description", "").strip()
    product_cost    = request.form.get("product_cost")
    category        = request.form.get("category",        "").strip()
    instrument_type = request.form.get("instrument_type", "").strip()
    brand           = request.form.get("brand",           "").strip()
    genre           = request.form.get("genre",           "").strip()
    level           = request.form.get("level",           "").strip()
    condition_status= request.form.get("condition_status","").strip()
    format_type     = request.form.get("format",          "N/A").strip()
    featured        = request.form.get("featured", 0)

    if not user_id:
        return jsonify({"message": "You must be signed in to add a product."}), 401

    if not all([product_name, product_description, product_cost, category]):
        return jsonify({"message": "Name, description, cost and category are required."}), 400

    if "product_photo" not in request.files:
        return jsonify({"message": "A main product photo is required."}), 400

    # Save main photo
    product_photo = request.files["product_photo"]
    filename = product_photo.filename
    product_photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO products
        (product_name, product_description, product_cost, product_photo,
         category, instrument_type, brand, genre, level,
         condition_status, format, featured, added_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        product_name, product_description, product_cost, filename,
        category, instrument_type, brand, genre, level,
        condition_status, format_type, featured, user_id
    ))
    connection.commit()
    new_product_id = cursor.lastrowid

    # Save extra images if any
    extra_images = request.files.getlist("extra_images")
    for img in extra_images:
        if img.filename:
            img_filename = img.filename
            img.save(os.path.join(app.config["UPLOAD_FOLDER"], img_filename))
            cursor.execute(
                "INSERT INTO product_images (product_id, image_name) VALUES (%s, %s)",
                (new_product_id, img_filename)
            )
    connection.commit()
    connection.close()
    return jsonify({"message": "Product added successfully!"}), 201


# ── EDIT PRODUCT ──────────────────────────────────────────────
@app.route("/api/edit_product/<int:product_id>", methods=["PUT"])
def edit_product(product_id):
    user_id         = request.form.get("user_id")
    product_name    = request.form.get("product_name",    "").strip()
    product_description = request.form.get("product_description", "").strip()
    product_cost    = request.form.get("product_cost")
    category        = request.form.get("category",        "").strip()
    instrument_type = request.form.get("instrument_type", "").strip()
    brand           = request.form.get("brand",           "").strip()
    genre           = request.form.get("genre",           "").strip()
    level           = request.form.get("level",           "").strip()
    condition_status= request.form.get("condition_status","").strip()
    format_type     = request.form.get("format",          "N/A").strip()
    featured        = request.form.get("featured", 0)

    if not user_id:
        return jsonify({"message": "You must be signed in to edit a product."}), 401

    connection = get_db()
    cursor = connection.cursor()

    # Make sure the product belongs to this user
    cursor.execute(
        "SELECT added_by FROM products WHERE product_id = %s",
        (product_id,)
    )
    product = cursor.fetchone()

    if not product:
        connection.close()
        return jsonify({"message": "Product not found."}), 404

    if str(product["added_by"]) != str(user_id):
        connection.close()
        return jsonify({"message": "You can only edit your own products."}), 403

    # Update main photo if a new one was uploaded
    if "product_photo" in request.files and request.files["product_photo"].filename:
        new_photo = request.files["product_photo"]
        filename  = new_photo.filename
        new_photo.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    else:
        cursor.execute(
            "SELECT product_photo FROM products WHERE product_id = %s",
            (product_id,)
        )
        filename = cursor.fetchone()["product_photo"]

    cursor.execute("""
        UPDATE products SET
            product_name=%s, product_description=%s, product_cost=%s,
            product_photo=%s, category=%s, instrument_type=%s, brand=%s,
            genre=%s, level=%s, condition_status=%s, format=%s, featured=%s
        WHERE product_id=%s
    """, (
        product_name, product_description, product_cost, filename,
        category, instrument_type, brand, genre, level,
        condition_status, format_type, featured, product_id
    ))
    connection.commit()
    connection.close()
    return jsonify({"message": "Product updated successfully!"}), 200

# ── DELETE PRODUCT ────────────────────────────────────────────
@app.route("/api/delete_product/<int:product_id>", methods=["DELETE"])
def delete_product(product_id):
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"message": "You must be signed in to delete a product."}), 401

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT added_by FROM products WHERE product_id = %s", (product_id,)
    )
    product = cursor.fetchone()

    if not product:
        connection.close()
        return jsonify({"message": "Product not found."}), 404

    if str(product["added_by"]) != str(user_id):
        connection.close()
        return jsonify({"message": "You can only delete your own products."}), 403

    # Delete associated images and cart/favourites rows first
    cursor.execute("DELETE FROM product_images WHERE product_id = %s", (product_id,))
    cursor.execute("DELETE FROM cart WHERE product_id = %s", (product_id,))
    cursor.execute("DELETE FROM favourites WHERE product_id = %s", (product_id,))
    cursor.execute("DELETE FROM ratings WHERE product_id = %s", (product_id,))
    cursor.execute("DELETE FROM products WHERE product_id = %s", (product_id,))

    connection.commit()
    connection.close()
    return jsonify({"message": "Product deleted successfully."}), 200


# ══════════════════════════════════════════════════════════════
#  CART
# ══════════════════════════════════════════════════════════════

# ── ADD TO CART ───────────────────────────────────────────────
@app.route("/api/cart/add", methods=["POST"])
def cart_add():
    user_id    = request.form.get("user_id")
    product_id = request.form.get("product_id")

    if not all([user_id, product_id]):
        return jsonify({"message": "User and product are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    # If item already in cart, increment quantity instead
    cursor.execute(
        "SELECT cart_id, quantity FROM cart WHERE user_id=%s AND product_id=%s",
        (user_id, product_id)
    )
    existing = cursor.fetchone()

    if existing:
        cursor.execute(
            "UPDATE cart SET quantity=%s WHERE cart_id=%s",
            (existing["quantity"] + 1, existing["cart_id"])
        )
    else:
        cursor.execute(
            "INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, 1)",
            (user_id, product_id)
        )

    connection.commit()
    connection.close()
    return jsonify({"message": "Item added to cart."}), 200

# ── ADD THIS ROUTE TO myapi.py (inside the CART section) ─────
# Place it right after the cart_add route (~line 456)

@app.route("/api/cart/decrement/<int:cart_id>", methods=["PUT"])
def cart_decrement(cart_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT quantity FROM cart WHERE cart_id = %s", (cart_id,))
    item = cursor.fetchone()

    if not item:
        connection.close()
        return jsonify({"message": "Cart item not found."}), 404

    if item["quantity"] <= 1:
        # Shouldn't happen (frontend removes instead), but handle it safely
        cursor.execute("DELETE FROM cart WHERE cart_id = %s", (cart_id,))
    else:
        cursor.execute(
            "UPDATE cart SET quantity = quantity - 1 WHERE cart_id = %s",
            (cart_id,)
        )

    connection.commit()
    connection.close()
    return jsonify({"message": "Quantity decreased."}), 200


# ── GET CART ──────────────────────────────────────────────────
@app.route("/api/cart/<int:user_id>", methods=["GET"])
def get_cart(user_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT c.cart_id, c.quantity, c.added_at,
               p.product_id, p.product_name, p.product_photo, p.product_cost
        FROM cart c
        JOIN products p ON c.product_id = p.product_id
        WHERE c.user_id = %s
        ORDER BY c.added_at DESC
    """, (user_id,))
    items = cursor.fetchall()
    connection.close()
    return jsonify(items), 200


# ── REMOVE ONE ITEM FROM CART ─────────────────────────────────
@app.route("/api/cart/remove/<int:cart_id>", methods=["DELETE"])
def cart_remove(cart_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM cart WHERE cart_id = %s", (cart_id,))
    connection.commit()
    connection.close()
    return jsonify({"message": "Item removed from cart."}), 200


# ── CLEAR CART (called after successful checkout) ─────────────
@app.route("/api/cart/clear/<int:user_id>", methods=["DELETE"])
def cart_clear(user_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
    connection.commit()
    connection.close()
    return jsonify({"message": "Cart cleared."}), 200


# ══════════════════════════════════════════════════════════════
#  FAVOURITES
# ══════════════════════════════════════════════════════════════

# ── TOGGLE FAVOURITE ──────────────────────────────────────────
@app.route("/api/favourites/toggle", methods=["POST"])
def toggle_favourite():
    user_id    = request.form.get("user_id")
    product_id = request.form.get("product_id")

    if not all([user_id, product_id]):
        return jsonify({"message": "User and product are required."}), 400

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT fav_id FROM favourites WHERE user_id=%s AND product_id=%s",
        (user_id, product_id)
    )
    existing = cursor.fetchone()

    if existing:
        cursor.execute("DELETE FROM favourites WHERE fav_id=%s", (existing["fav_id"],))
        connection.commit()
        connection.close()
        return jsonify({"message": "Removed from favourites.", "status": "removed"}), 200
    else:
        cursor.execute(
            "INSERT INTO favourites (user_id, product_id) VALUES (%s, %s)",
            (user_id, product_id)
        )
        connection.commit()
        connection.close()
        return jsonify({"message": "Added to favourites.", "status": "added"}), 200


# ── GET FAVOURITES ────────────────────────────────────────────
@app.route("/api/favourites/<int:user_id>", methods=["GET"])
def get_favourites(user_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT f.fav_id, f.added_at,
               p.product_id, p.product_name, p.product_photo, p.product_cost,
               ROUND(AVG(r.stars), 1) AS avg_rating
        FROM favourites f
        JOIN products p ON f.product_id = p.product_id
        LEFT JOIN ratings r ON p.product_id = r.product_id
        WHERE f.user_id = %s
        GROUP BY f.fav_id
        ORDER BY f.added_at DESC
    """, (user_id,))
    items = cursor.fetchall()
    connection.close()
    return jsonify(items), 200


# ══════════════════════════════════════════════════════════════
#  RATINGS
# ══════════════════════════════════════════════════════════════

# ── ADD / UPDATE RATING ───────────────────────────────────────
@app.route("/api/ratings/add", methods=["POST"])
def add_rating():
    user_id    = request.form.get("user_id")
    product_id = request.form.get("product_id")
    stars      = request.form.get("stars")
    comment    = request.form.get("comment", "").strip()

    if not all([user_id, product_id, stars]):
        return jsonify({"message": "User, product and star rating are required."}), 400

    if not (1 <= int(stars) <= 5):
        return jsonify({"message": "Stars must be between 1 and 5."}), 400

    connection = get_db()
    cursor = connection.cursor()

    # If user already rated this product, update instead of insert
    cursor.execute(
        "SELECT rating_id FROM ratings WHERE user_id=%s AND product_id=%s",
        (user_id, product_id)
    )
    existing = cursor.fetchone()

    if existing:
        cursor.execute(
            "UPDATE ratings SET stars=%s, comment=%s WHERE rating_id=%s",
            (stars, comment, existing["rating_id"])
        )
    else:
        cursor.execute(
            "INSERT INTO ratings (user_id, product_id, stars, comment) VALUES (%s,%s,%s,%s)",
            (user_id, product_id, stars, comment)
        )

    connection.commit()
    connection.close()
    return jsonify({"message": "Rating submitted successfully!"}), 200


# ── GET RATINGS FOR A PRODUCT ─────────────────────────────────
@app.route("/api/ratings/<int:product_id>", methods=["GET"])
def get_ratings(product_id):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("""
        SELECT r.rating_id, r.stars, r.comment, r.created_at,
               u.first_name, u.last_name
        FROM ratings r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.product_id = %s
        ORDER BY r.created_at DESC
    """, (product_id,))
    ratings = cursor.fetchall()
    connection.close()
    return jsonify(ratings), 200


# ══════════════════════════════════════════════════════════════
#  PAYMENTS
# ══════════════════════════════════════════════════════════════

@app.route("/api/mpesa_payment", methods=["POST"])
def mpesa_payment():
    amount = request.form.get("amount")
    phone  = request.form.get("phone")

    consumer_key    = "GTWADFxIpUfDoNikNGqq1C3023evM6UH"
    consumer_secret = "amFbAoUByPV2rM5A"
    api_url         = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

    r            = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    access_token = "Bearer " + r.json()["access_token"]

    timestamp  = datetime.datetime.today().strftime("%Y%m%d%H%M%S")
    passkey    = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
    short_code = "174379"
    password   = base64.b64encode((short_code + passkey + timestamp).encode()).decode("utf-8")

    payload = {
        "BusinessShortCode": short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": short_code,
        "PhoneNumber": phone,
        "CallBackURL": "https://modcom.co.ke/api/confirmation.php",
        "AccountReference": "Acoustiq",
        "TransactionDesc": "Acoustiq Purchase"
    }

    headers  = {"Authorization": access_token, "Content-Type": "application/json"}
    url      = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    requests.post(url, json=payload, headers=headers)

    return jsonify({"message": "Please complete the payment on your phone. We will deliver shortly!"}), 200


# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(debug=True)