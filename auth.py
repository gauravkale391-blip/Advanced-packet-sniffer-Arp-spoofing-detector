USERS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "analyst": {"password": "analyst123", "role": "Analyst"},
    "viewer": {"password": "viewer123", "role": "Viewer"},
}


def verify_login(username, password):
    user = USERS.get(username)
    if user and user["password"] == password:
        return user["role"]
    return None
