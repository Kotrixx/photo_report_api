import bcrypt
from cryptography.fernet import Fernet


# Función para encriptar una contraseña
def encriptar_contraseña(contraseña):
    # Convertir la contraseña a bytes
    contraseña_bytes = contraseña.encode('utf-8')
    # Generar el salt
    salt = bcrypt.gensalt()
    # Crear el hash
    hash_contraseña = bcrypt.hashpw(contraseña_bytes, salt)
    return hash_contraseña

# Función para verificar una contraseña
def verificar_contraseña(contraseña, hash_guardado):
    # Convertir la contraseña a bytes
    contraseña_bytes = contraseña.encode('utf-8')
    # Verificar la contraseña
    return bcrypt.checkpw(contraseña_bytes, hash_guardado)

# Ejemplo de uso
if __name__ == "__main__":
    SECRET_KEY = Fernet.generate_key()
    print(SECRET_KEY)
    cipher = Fernet(SECRET_KEY)
