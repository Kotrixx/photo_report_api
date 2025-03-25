from urllib.parse import quote_plus

import bcrypt
import pymongo
from bson import DBRef
from faker import Faker
import random
from datetime import datetime

from pymongo import MongoClient

fake = Faker()

# Conexión MongoDB
USERNAME = quote_plus("kotsbw03")
PASSWORD = quote_plus("kots.bw03")

MONGO_URL = (f"mongodb+srv://{USERNAME}:{PASSWORD}"
             f"@cluster0.qj1v8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

client = MongoClient(MONGO_URL)
db = client["ecommerce_onestore"]
collection = db["products"]

# Step 1: Define resources
resource_definitions = [
    ("products", "Manage ecommerce products"),
    ("ads", "Promotional ads in the store"),
    ("offers", "Special discounts and offers"),
    ("presale", "Manage pre-sale and reservations"),
    ("users", "Manage user accounts")
]

# Step 2: Insert resources
resource_ids = {}
for name, description in resource_definitions:
    result = db.resources.insert_one({
        "resource_name": name,
        "description": description
    })
    resource_ids[name] = result.inserted_id
print("✅ Resources inserted successfully.")

# Step 3: Create 'admin' role with full permissions
access_control = []
for res_id in resource_ids.values():
    access_control.append({
        "resource": DBRef("resources", res_id),
        "permissions": ["read", "create", "update", "delete"]
    })

admin_role = {
    "role_name": "admin",
    "access_control": access_control
}
role_result = db.roles.insert_one(admin_role)
print("✅ Admin role created.")

# Step 4: Create admin user with hashed password
plain_password = "admin123"
hashed_password = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())

admin_user = {
    "first_name": "Ricardo",
    "last_name": "Bravo",
    "second_last_name": "Wong",
    "email": "ricardo.bravo@example.com",
    "password": hashed_password.decode("utf-8"),
    "role": DBRef("roles", role_result.inserted_id),
    "status": "active",
    "date_created": datetime.utcnow(),
    "last_login": None,
    "preferences": {
        "contact_info": None
    }
}
db.users.insert_one(admin_user)
print("✅ Admin user created with email: ricardo.bravo@example.com and password: admin123")