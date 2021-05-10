from flask import Flask, request, url_for, render_template, flash, session, g
from werkzeug.utils import secure_filename
from config import *
from helper import *
import os
import time # for debugging

app = Flask(__name__)

@app.route('/')
def main():
    print('[debug] upload dir: ', Config.UPLOAD_DIR)
    return render_template('index.html')

@app.route('/upload', methods=['POST','GET'])
def upload():
    error = None
    
    if request.method == 'POST':
        g.file = request.files['file']
        file = g.file
        filename = os.path.join(Config.UPLOAD_DIR, secure_filename(file.filename))
        file.save(filename)    
        
        g.filetype = get_filetype(filename)
        
        if g.filetype == None:
            error = 'not surpported type. ( give me ELF or PE )'
            os.remove(filename)
        else:
            flash('file upload success')    
    elif request.method == 'GET':
        g.file = None
        
    return render_template('upload.html', error=error)

@app.route('/cfgview', methods=['GET'])
def cfgview():
    error = None
    file = request.args.get("file")
    filelist = get_filelist()
    
    if file is None:    # file이 없는 경우, 업로드된 파일 리스트만 보여줌.
        return render_template('cfgview.html', filelist=filelist, target=None, cfg=None)
    else:   # get 요청 받은 file의 main 함수 cfg를 보여줌.
        func = request.args.get("func")
        if func == None:
            func = "main"
        g.r = get_r2pipe(file)
        cfg = get_cfg(g.r, func)
        funcdict = get_funcdict(g.r)
        return render_template('cfgview.html', filelist=filelist, target=file, cfg=cfg, funcdict=funcdict)

if __name__ == "__main__":
    app.debug = True
    app.config.from_object(Config)
    
    app.run(host='0.0.0.0', port=1337)