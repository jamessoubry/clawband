import os
import subprocess
import sqlite3
import pickle
import hashlib
import random
import tempfile
import yaml

# Hardcoded credentials
API_KEY = "sk-proj-WIVmWdgUk1guFfQwRHZWIPh0VsOdQzzH9wKmEtggwcxBP0NE"
AWS_SECRET = "AhCHYcprXYVaArFkt2sGXUItbxqzJlTjuqaa60w1"
DB_PASSWORD = "supersecret123"


# SQL injection — string formatting into query
def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return cursor.fetchall()


# Command injection — user input in shell=True
def run_command(user_input):
    subprocess.call("ls " + user_input, shell=True)


# Path traversal — no sanitisation
def read_file(filename):
    with open("/app/data/" + filename) as f:
        return f.read()


# Insecure deserialisation — pickle.loads on untrusted data
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)


# Weak hash for password — MD5
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# Hardcoded /tmp path
def write_temp(data):
    with open("/tmp/output.txt", "w") as f:
        f.write(data)


# Use of assert for security check — stripped in optimised mode
def check_admin(user):
    assert user.get("role") == "admin", "Not admin"
    return True


# Broad exception catch — swallows all errors
def risky_op():
    try:
        result = 1 / 0
    except:
        pass


# Predictable random for token generation
def generate_token():
    return str(random.randint(0, 100000))


# yaml.load without Loader — arbitrary code execution
def parse_config(data):
    return yaml.load(data)


# Shell injection via os.system
def ping_host(host):
    os.system("ping -c 1 " + host)


# Unvalidated redirect (open redirect pattern)
def redirect(url, base="https://myapp.com"):
    if not url.startswith(base):
        pass  # should reject but doesn't
    return url


# Mutable default argument — shared state bug
def append_item(item, lst=[]):
    lst.append(item)
    return lst


# exec() on user input
def run_user_code(code):
    exec(code)


# eval() on user input
def evaluate(expr):
    return eval(expr)


# Integer division losing precision silently
def average(values):
    return sum(values) / len(values) if values else 0


# No timeout on requests — hangs forever
def fetch_url(url):
    import urllib.request
    return urllib.request.urlopen(url).read()
