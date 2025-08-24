# app.py
from flask import flash
import random
from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from db_config import db_config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from functools import wraps
from flask import request, jsonify, render_template
from math import ceil
from flask import session, redirect, url_for, request, flash
import stripe
import os, json
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
import time
import uuid
import numpy as np
from ml.semantic import SemanticIndex
import json
import os
import uuid
from flask import flash, request, redirect, url_for, render_template
from datetime import datetime


import mysql.connector







load_dotenv()
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")

app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",          
        password="Kunal$21",  
        database="shopping_app"    
    )



# Build/load semantic index once (avoid double-load in reloader)
if not hasattr(app, "semantic"):
    app.semantic = SemanticIndex(get_db_connection)


app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
app.debug = True



    # Flask-Mail config (use your actual Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kunalchoramale2@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'kunalchoramale2@gmail.com'

mail = Mail(app)



def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.template_filter('fromjson')
def fromjson_filter(s):
    try:
        return json.loads(s)
    except Exception:
        return []
    
    
@app.route('/')
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    conn.close()

    # Parse images JSON into Python list + set main_image
    for product in products:
        try:
            images = json.loads(product['images']) if product['images'] else []
        except Exception:
            images = []
        product['main_image'] = images[0] if images else 'default.png'

    return render_template("user/index.html", products=products)


@app.route('/search')
def search():
    q = (request.args.get('q') or '').strip()
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = 24
    offset = (page - 1) * per_page

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    products = []
    total = 0
    used_semantic = False

    if q:
        # 1) Try semantic search
        try:
            hits = app.semantic.search(q, topk=200)  # grab more, paginate in SQL
            if hits:
                used_semantic = True
                id_order = [pid for pid, _ in hits]
                # paginate ids manually
                page_ids = id_order[offset: offset + per_page]
                if page_ids:
                    placeholders = ",".join(["%s"] * len(page_ids))
                    cur.execute(f"""
                        SELECT id, name, description, price, images
                        FROM products
                        WHERE id IN ({placeholders})
                    """, tuple(page_ids))
                    rows = cur.fetchall()
                    # keep original semantic order
                    order = {pid: i for i, pid in enumerate(page_ids)}
                    rows.sort(key=lambda r: order.get(r['id'], 999999))
                    # set image
                    for r in rows:
                        try:
                            imgs = json.loads(r.get('images') or '[]')
                        except Exception:
                            imgs = []
                        r['image_url'] = f"/static/images/products/{imgs[0]}" if imgs else "/static/images/products/default.png"
                    products = rows
                    total = len(id_order)
        except Exception:
            used_semantic = False

    if not used_semantic:
        # 2) Fallback to your existing LIKE/FULLTEXT flow (kept simple here)
        q_like = f"%{q}%"
        cur.execute("""
            SELECT SQL_CALC_FOUND_ROWS id, name, description, price, images
            FROM products
            WHERE name LIKE %s OR description LIKE %s
            ORDER BY name ASC
            LIMIT %s OFFSET %s
        """, (q_like, q_like, per_page, offset))
        rows = cur.fetchall()
        cur.execute("SELECT FOUND_ROWS()")
        total = cur.fetchone()['FOUND_ROWS()'] if isinstance(cur.fetchone(), dict) else total
        # images
        for r in rows:
            try:
                imgs = json.loads(r.get('images') or '[]')
            except Exception:
                imgs = []
            r['image_url'] = f"/static/images/products/{imgs[0]}" if imgs else "/static/images/products/default.png"
        products = rows

    cur.close(); conn.close()
    pages = max(1, (total + per_page - 1) // per_page)

    return render_template('user/search.html',
                           products=products,
                           query=q,
                           page=page,
                           pages=pages,
                           total=total,
                           used_fulltext=not used_semantic,
                           used_semantic=used_semantic)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')


        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                           (name, email, password))
            conn.commit()
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            return f"Error: {err}"
        finally:
            conn.close()
    return render_template('user/register.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT name, email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return "User not found", 404

    return render_template('user/profile.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password_input):
            session['user_id'] = user['id']
            session['email'] = user['email']
            return redirect(url_for('home'))  # or wherever
        else:
            return "Invalid email or password"
    return render_template('user/login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/add_to_cart/<int:product_id>', methods=['POST', 'GET'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # force login if not logged in

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # check if product already in cart for this user
    cursor.execute("SELECT * FROM cart WHERE user_id = %s AND product_id = %s",
                   (session['user_id'], product_id))
    existing = cursor.fetchone()

    if existing:
        # if already in cart → increase quantity
        cursor.execute("UPDATE cart SET quantity = quantity + 1 WHERE user_id = %s AND product_id = %s",
                       (session['user_id'], product_id))
    else:
        # if not in cart → insert new row
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                       (session['user_id'], product_id, 1))

    conn.commit()
    conn.close()

    return redirect(url_for('cart'))


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.id, p.name, p.price, c.quantity, p.id AS product_id
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
    """, (session['user_id'],))

    cart_items = cursor.fetchall()

    # calculate total
    total = sum(item['price'] * item['quantity'] for item in cart_items)

    conn.close()
    return render_template('user/cart.html', cart_items=cart_items, total=total)



@app.route('/update_cart', methods=['POST'])
def update_cart_bulk():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Remove a single item if Remove button pressed
    remove_single = request.form.get('remove_item')
    if remove_single:
        cursor.execute("DELETE FROM cart WHERE id=%s AND user_id=%s", (remove_single, user_id))
        conn.commit()

    # Update quantities if Update Cart pressed
    if 'update_quantities' in request.form:
        for key, value in request.form.items():
            if key.startswith('quantity_'):
                cart_id = key.split('_')[1]
                quantity = int(value)
                if quantity > 0:
                    cursor.execute("UPDATE cart SET quantity=%s WHERE id=%s AND user_id=%s",
                                   (quantity, cart_id, user_id))
                else:
                    cursor.execute("DELETE FROM cart WHERE id=%s AND user_id=%s", (cart_id, user_id))
        conn.commit()

    # Fetch updated cart items to recalc total
    cursor.execute("""
        SELECT c.id, p.name, p.price, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id=%s
    """, (user_id,))
    cart_items = cursor.fetchall()

    total = sum(item['price'] * item['quantity'] for item in cart_items)
    conn.close()

    # Proceed to payment if button clicked
    if 'proceed_payment' in request.form:
        if not cart_items:
            return redirect(url_for('cart'))  # nothing to pay
        line_items = [{
            'price_data': {
                'currency': 'gbp',
                'product_data': {'name': item['name']},
                'unit_amount': int(item['price'] * 100),
            },
            'quantity': item['quantity'],
        } for item in cart_items]

        session_stripe = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=line_items,
            mode='payment',
            success_url=url_for('payment_success', _external=True),
            cancel_url=url_for('cart', _external=True)
        )
        return redirect(session_stripe.url)

    # Render cart page again with updated quantities and total
    return render_template('user/cart.html', cart_items=cart_items, total=total)





@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    quantity = int(request.form.get('quantity', 1))
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    if quantity > 0:
        cursor.execute("UPDATE cart SET quantity = %s WHERE user_id = %s AND product_id = %s",
                       (quantity, user_id, product_id))
    else:
        cursor.execute("DELETE FROM cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
    conn.commit()
    conn.close()
    return redirect(url_for('cart'))



@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('''
        SELECT p.name, p.price, c.quantity
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
    ''', (user_id,))
    items = cursor.fetchall()
    conn.close()

    # Prepare Stripe line items
    line_items = [{
        'price_data': {
            'currency': 'gbp',
            'product_data': {'name': item['name']},
            'unit_amount': int(item['price'] * 100),  # in pence
        },
        'quantity': item['quantity'],
    } for item in items]

    session_stripe = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=line_items,
        mode='payment',
        success_url=url_for('payment_success', _external=True),
        cancel_url=url_for('cart', _external=True)
    )

    return redirect(session_stripe.url)




@app.route('/success')
def payment_success():
    #user_id = session.get('user_id')
    #if user_id:
        # Clear cart after successful payment
     #   conn = get_db_connection()
      #  cursor = conn.cursor()
      if 'user_id' in session:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
        conn.commit()
        conn.close()
   
        return render_template('user/success.html')


@app.route('/remove_from_cart/<int:item_id>')
def remove_from_cart(item_id):
    if 'user_id' in session:
        user_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
        conn.commit()
        conn.close()
    return redirect(url_for('cart'))




@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        mobile = request.form['mobile']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s AND mobile = %s", (email, mobile))
        user = cursor.fetchone()
        conn.close()

        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['otp'] = otp

            # Send email
            msg = Message('Your OTP for password reset', sender='your_email@gmail.com', recipients=[email])
            msg.body = f"Your OTP is {otp}"
            mail.send(msg)

            # TODO: Integrate SMS sending (next step)

            return redirect(url_for('verify_otp'))
        else:
            return "Email and Mobile number do not match."
    
    return render_template('user/forgot_password.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session.get('otp'):
            return redirect(url_for('reset_password'))
        else:
            return "Invalid OTP"
    return render_template('user/verify_otp.html')



@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        email = session.get('reset_email')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
        conn.commit()
        conn.close()

        session.pop('reset_email', None)
        session.pop('otp', None)

        return redirect(url_for('login'))

    return render_template('user/reset_password.html')


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Product
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    # Images
    cursor.execute("SELECT image_filename FROM product_images WHERE product_id = %s", (product_id,))
    images = [row['image_filename'] for row in cursor.fetchall()]

    # --- Similar products (content-based via BERT) ---
    similar = []
    try:
        hits = app.semantic.similar_products(product_id, topk=8)  # [(id,score)]
        if hits:
            sim_ids = [pid for pid, _ in hits]
            placeholders = ",".join(["%s"] * len(sim_ids))
            cursor.execute(f"""
                SELECT id, name, price, images
                FROM products
                WHERE id IN ({placeholders})
            """, tuple(sim_ids))
            rows = cursor.fetchall()
            # preserve order
            order = {pid: i for i, pid in enumerate(sim_ids)}
            rows.sort(key=lambda r: order.get(r['id'], 999999))
            for r in rows:
                try:
                    imgs = json.loads(r.get('images') or '[]')
                except Exception:
                    imgs = []
                r['image_url'] = f"/static/images/products/{imgs[0]}" if imgs else "/static/images/products/default.png"
            similar = rows
    except Exception:
        similar = []

    conn.close()
    return render_template("user/product_detail.html", product=product, images=images, similar_products=similar)








# ----------------------------
# ADMIN ROUTES
# ----------------------------

# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
        admin = cursor.fetchone()
        conn.close()

        if admin and bcrypt.check_password_hash(admin['password'], password):
            session['admin_id'] = admin['id']
            session['admin_email'] = admin['email']
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for('admin_login'))

    return render_template('admin/admin_login.html')


# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash("Please log in to access admin dashboard", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch some dashboard stats
    cursor.execute("SELECT COUNT(*) AS total_products FROM products")
    total_products = cursor.fetchone()['total_products']

    cursor.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cursor.fetchone()['total_users']

    cursor.execute("SELECT COUNT(*) AS total_orders FROM orders")
    total_orders = cursor.fetchone()['total_orders']

    conn.close()

    return render_template(
        'admin/admin_dashboard.html',
        total_products=total_products,
        total_users=total_users,
        total_orders=total_orders
    )


# Admin Logout
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    session.pop('admin_email', None)
    flash("You have been logged out", "info")
    return redirect(url_for('admin_login'))







# Add Product
UPLOAD_FOLDER = 'static/images/products'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# This function must be defined BEFORE it is called in the route below.
def allowed_file(filename):
    """
    Checks if a file's extension is in the list of allowed extensions.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Add Product
@app.route('/admin/add-product', methods=['GET', 'POST'])
def admin_add_product():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        description = request.form['description']
        stock = request.form['stock']
        category = request.form['category']

        images_list = []
        if 'images' in request.files:
            files = request.files.getlist('images')
            for file in files:
                # The allowed_file() function is now correctly defined above.
                if file and allowed_file(file.filename):
                    # Use UUID to prevent filename conflicts
                    filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(save_path)
                    images_list.append(filename)

        # DEBUG
        print("DEBUG - Uploaded images:", images_list)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Insert into products
        cursor.execute(
            "INSERT INTO products (name, price, description, stock, category, images) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, price, description, stock, category, json.dumps(images_list))
        )
        product_id = cursor.lastrowid

        # Insert into product_images
        for img in images_list:
            cursor.execute(
                "INSERT INTO product_images (product_id, image_filename) VALUES (%s, %s)",
                (product_id, img)
            )

        conn.commit()
        conn.close()

        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_manage_products'))

    return render_template('admin/admin_add_product.html')




# Edit Product
@app.route('/admin/edit-product/<int:product_id>', methods=['GET', 'POST'])
def admin_edit_product(product_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch product details
    cursor.execute("SELECT * FROM products WHERE id=%s", (product_id,))
    product = cursor.fetchone()
    if not product:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for("admin_manage_products"))

    # Fetch images from the product_images table for consistency
    cursor.execute("SELECT image_filename FROM product_images WHERE product_id=%s", (product_id,))
    images = [row['image_filename'] for row in cursor.fetchall()]

    if request.method == "POST":
        # Form data
        name = request.form["name"]
        price = request.form["price"]
        description = request.form["description"]
        stock = request.form["stock"]
        category = request.form["category"]

        # Handle new images
        files = request.files.getlist("images")
        new_images = []

        for file in files:
            if file and file.filename != "" and allowed_file(file.filename):
                filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(save_path)
                new_images.append(filename)

        if new_images:
            # 1️⃣ Delete old images from disk
            for old_img in images:  # Use the 'images' list fetched from the database
                old_path = os.path.join(app.config["UPLOAD_FOLDER"], old_img)
                if os.path.exists(old_path):
                    os.remove(old_path)

            # 2️⃣ Update products table with new image URLs
            images_json = json.dumps(new_images)
            cursor.execute("""
                UPDATE products
                SET name=%s, price=%s, description=%s, stock=%s, category=%s, images=%s
                WHERE id=%s
            """, (name, price, description, stock, category, images_json, product_id))

            # 3️⃣ Update product_images table
            cursor.execute("DELETE FROM product_images WHERE product_id=%s", (product_id,))
            for img in new_images:
                cursor.execute(
                    "INSERT INTO product_images (product_id, image_filename) VALUES (%s,%s)",
                    (product_id, img)
                )
        else:
            # No new images, keep old ones
            cursor.execute("""
                UPDATE products
                SET name=%s, price=%s, description=%s, stock=%s, category=%s
                WHERE id=%s
            """, (name, price, description, stock, category, product_id))

        conn.commit()
        conn.close()
        flash("Product updated successfully!", "success")
        return redirect(url_for("admin_manage_products"))

    # GET request: render edit form with product and its images
    conn.close()
    return render_template("admin/admin_edit_product.html", product=product, images=images)





# Delete Product
@app.route('/admin/delete-product/<int:product_id>', methods=['POST'])
def admin_delete_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch product to get current images
    cursor.execute("SELECT * FROM products WHERE id=%s", (product_id,))
    product = cursor.fetchone()

    if not product:
        conn.close()
        flash("Product not found.", "error")
        return redirect(url_for("admin_manage_products"))

    try:
        # 1️⃣ Delete product images from disk
        if product['images']:
            old_images = json.loads(product['images'])
            for img in old_images:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], img)
                if os.path.exists(old_path):
                    os.remove(old_path)

        # 2️⃣ Delete related entries from product_images table
        cursor.execute("DELETE FROM product_images WHERE product_id=%s", (product_id,))

        # 3️⃣ Delete related entries from cart table
        cursor.execute("DELETE FROM cart WHERE product_id=%s", (product_id,))

        # 4️⃣ Finally, delete the product itself
        cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
        app.semantic.delete_product(product_id)

        conn.commit()
        flash("Product deleted successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error deleting product: {str(e)}", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_manage_products"))




# Manage Products
@app.route('/admin/manage-products')
def admin_manage_products():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products ORDER BY id DESC")
    products = cursor.fetchall()
    conn.close()

    return render_template('admin/manage_products.html', products=products)


# Manage Users
@app.route('/admin/manage-users')
def admin_manage_users():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin/manage_users.html', users=users)


# Manage Orders
@app.route('/admin/manage-orders')
def admin_manage_orders():
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders ORDER BY id DESC")
    orders = cursor.fetchall()
    conn.close()

    return render_template('admin/manage_orders.html', orders=orders)



if __name__ == '__main__':
    app.run(debug=True)


