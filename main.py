import bcrypt

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
    # Solicitar la contraseña al usuario
    contraseña_original = input("Introduce tu contraseña: ")

    # Encriptar la contraseña
    hash_generado = encriptar_contraseña(contraseña_original)
    print(f"Hash generado: {hash_generado.decode('utf-8')}")

    # Verificar la contraseña
    contraseña_verificar = input("Vuelve a introducir tu contraseña para verificar: ")
    if verificar_contraseña(contraseña_verificar, hash_generado):
        print("¡Contraseña verificada con éxito!")
    else:
        print("La contraseña no coincide.")
