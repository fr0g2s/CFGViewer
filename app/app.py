from flask import Flask, request, url_for, render_template, flash, session, g, jsonify
from werkzeug.utils import secure_filename
from config import *
from upload_helper import *
from cfgview_helper import *
from cfgjson_helper import *
import os
import json
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
        g.file = file
        func = request.args.get("func")
        if func == None:
            func = "main"
        r = get_r2pipe(file)
        cfg, width = get_cfg(r, func)
        funcdict = get_funcdict(r)
        return render_template('cfgview.html', filelist=filelist, target=file, func=func, cfg=cfg, width=width, funcdict=funcdict)

@app.route("/cfgjson", methods=["GET"])
def cfgjson():
    file = request.args.get("file")
    func = request.args.get("func")

    if file is None:
        return "no file"
    else:
        r = get_r2pipe(file)
        cfg_json = get_cfgjson(r, func)
        return jsonify(cfg_json)

@app.route("/diagram")
def diagram():
    # mermaid test page
    return render_template('diagram.html')

if __name__ == "__main__":
    app.debug = True
    app.config.from_object(Config)
    
    app.run(host='0.0.0.0', port=1337)