import os

def validate_file_path(file_path):
    if not os.path.isabs(file_path):
        raise ValueError("Path must be absolute")
    # Ajoute d'autres validations si nécessaire
