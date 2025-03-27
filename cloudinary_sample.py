from datetime import datetime

# Timestamp UNIX
exp_timestamp = 1743057187

# Convertir a fecha legible
exp_date = datetime.utcfromtimestamp(exp_timestamp)
print("Fecha de expiración:", exp_date)
