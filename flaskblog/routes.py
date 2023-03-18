import os
import secrets
#from PIL import Image
from flask import Flask, request, Response
from uuid import uuid4
import json
app = Flask(__name__)

users = []
DBNAME = "users.json"
active_logins = []

def save_users(users) -> None:
    with open("users.json", "w") as f:
        json.dump(users, f)

def user_already_exists(users, username) -> bool:
    pass

def not_authenticated(token):
    if token in active_logins:
        return False
    
    return True

def invalid_user(users, creds) -> bool:
    for user in users:
        if user.get("username") == creds.get("username") and user.get("password") == creds.get("password"):
            return False

    return True

def get_user_by_username(users, username) -> dict:
    for user in users:
        if user.get("username") == username:
            return user
    
    return {}

def update_users(users, add_user= {}, del_user = "", update_user = {}):
    global user
    if add_user:
        users.append(add_user)
    
    if del_user:
        updated_users = []
        for user in users:
            if user.get("username") != del_user:
                updated_users.append(user)
        users = updated_users
        save_users(users)
        
    if update_user:
        updated_users = []
        for user in users:
            if user.get("username") == update_user.get("username"):
                updated_users.append(update_user)
                continue
        users = updated_users
        save_users(users)
        
@app.route("/user", methods=['POST'])
def register_new_user():
    """
        user = {
            "fullname": "",
            "age": "",
            "username": "",
            "password": ""
        }
        validate user details:
        1. All attributes are provided  are provideded or not
        2. Validate attributes data types
        3. extra info(not accepted)
        4. username should be unique
    """
    new_user = request.json # dict
    user_id = len(users) + 1
    new_user["user_id"] = user_id
    users.append(new_user)
    save_users(users)
    return new_user

@app.route("/user", methods=['GET'])
def get_all_user():
    headers = request.headers
    if not_authenticated(headers.get("token")):
        return Response(response=json.dumps({"msg": "Please do login"}).encode(),content_type="application/json", status=401)
    return users

@app.route("/user/<username>", methods = ["GET"])
def get_single_user(username):
    headers = request.headers
    if not_authenticated(headers.get("token")):
        return Response(response=json.dumps({"msg": "Please do login"}).encode(),content_type="application/json", status=401)    
    user = get_user_by_username(users, username)
    return user


@app.route("/user/<username>", methods = ["PATCH"])
def update_single_user(username):
    headers = request.headers
    if not_authenticated(headers.get("token")):
        return Response(response=json.dumps({"msg": "Please do login"}).encode(),content_type="application/json", status=401)    
    user = get_user_by_username(users, username)
    req_body = request.json
    user = {**user, **req_body}
    update_users(users, update_user=user)
    return user


@app.route("/user/<username>", methods = ["DELETE"])
def delete_single_user(username):
    headers = request.headers
    if not_authenticated(headers.get("token")):
        return Response(response=json.dumps({"msg": "Please do login"}).encode(),content_type="application/json", status=401)    
    update_users(users, del_user=username)
    return user



@app.route("/login", methods=['POST'])
def do_login():
    """
        creds = {
            "username" : "Harish",
            "password": "password"
        }
        validate user details:
        1. username and password are provideded or not
        2. extra info(not accepted)
    """
    creds = request.json
    
    if invalid_user(users, creds):
        return Response(response=json.dumps({"msg": "Invalid user"}).encode(),content_type="application/json", status=401)
    
    token = str(uuid4())
    active_logins.append(token)
    return Response(response=json.dumps({"msg": "Login Successfully"}).encode(),content_type="application/json",status=200, headers={"token": token})



with open("users.json", "r") as f:
    users = json.load(f)

if __name__=='__main__':
	app.run(debug=True)