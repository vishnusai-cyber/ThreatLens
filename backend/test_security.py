from app.auth.security import hash_password, verify_password

hashed = hash_password("admin123")

print("Hashed Password:", hashed)
print("Correct Password:", verify_password("admin123", hashed))
print("Wrong Password:", verify_password("wrongpassword", hashed))