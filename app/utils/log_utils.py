import logging
from datetime import datetime

# Configura el sistema de logging
logging.basicConfig(
    filename='./auth_logs.log',  # Nombre del archivo de logs
    level=logging.INFO,          # Nivel de logging (INFO, WARNING, ERROR, etc.)
    format='%(asctime)s - %(levelname)s - %(message)s'  # Formato del log
)

# Silenciar logs de passlib y bcrypt
logging.getLogger("passlib").setLevel(logging.ERROR)
logging.getLogger("bcrypt").setLevel(logging.ERROR)

def log_auth_attempt(email_or_username: str, success: bool, metadata: dict):
    """
    Guarda un intento de autenticación en el archivo de logs.
    :param email_or_username: El email o username del usuario.
    :param success: True si el intento fue exitoso, False si no.
    :param metadata: Metadatos adicionales (IP, user-agent, etc.).
    """
    status = "SUCCESS" if success else "FAILED"

    # Crear una copia de los metadatos para no modificar el original
    log_metadata = metadata.copy()

    # Eliminar información sensible (si existe)
    log_metadata.pop("password", None)  # Elimina la contraseña si está presente

    log_message = f"Auth attempt by {email_or_username} - {status} - Metadata: {log_metadata}"
    logging.info(log_message)

# Ejemplo de uso
metadata = {
    "ip": "192.168.1.1",
    "user_agent": "Mozilla/5.0",
    "password": "supersecret"  # Esto no se incluirá en el log
}

log_auth_attempt(
    email_or_username="user@example.com",
    success=True,
    metadata=metadata
)