import os

base_dir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = "i don't know what is this"
    DEBUG = True
    UPLOAD_DIR = os.path.join(base_dir, "binary")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

# 디버깅 할 때 마다 True/False 고치는거 귀찮다. False에 주석만 추가/삭제 하자.
HELPER_DEBUG = True
HELPER_DEBUG = False
        

key = Config.SECRET_KEY