import os

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = "i don't know what is this"
    DEBUG = True
    UPLOAD_DIR = os.path.join(base_dir, "binary")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

HELPER_DEBUG = False
        

key = Config.SECRET_KEY