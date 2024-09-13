import bcrypt

# Función para generar hash de una contraseña
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

password = "miContraseñaSegura"
hashed_password = hash_password(password)
print("Hash de la contraseña:", hashed_password)


def verificar_password(password_ingresada, hashed_password):
    return bcrypt.checkpw(password_ingresada.encode(), hashed_password)

password_ingresada = "miContraseñaSegura"
if verificar_password(password_ingresada, hashed_password):
    print("Acceso permitido")
else:
    print("Acceso denegado")

    