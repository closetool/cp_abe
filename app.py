import base64
from crypt import methods
import json
import os
import shutil
import sys
import hashlib
import resource
from flask import Flask, redirect, render_template, request, make_response, send_from_directory, abort, Response
import mimetypes

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc

app = Flask(__name__,template_folder='static',static_folder='static',static_url_path='/static')

authn_cookie_key = 'Authentication'
user_dir = './users'
uid_loc = './uid.txt'
resources_dir = "./resources"

pk_loc = './pk.json'
msk_loc = './msk.json'

def check_dirs_exists(dirs):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)

def check_file_exists(files):
    for f in files:
        if not os.path.exists(f):
            with open(f,"w"):
                pass

check_dirs_exists([user_dir,resources_dir])
check_file_exists([uid_loc,pk_loc,msk_loc])

def authen(authn_cookie):
    try:
        authn_user = json.loads(authn_cookie)
        user = {}
        with open(os.path.join(user_dir, authn_user["username"]),'r') as f:
            user = json.loads(f.readline())
        if authn_user["password"] != hashlib.md5(user["password"].encode(encoding='UTF-8')).hexdigest():
            return False, {}
    except:
        return False
    return True, user


@app.route("/")
def home2():
    return redirect('/index.html')

@app.route("/index.html")
def home():
    authn_cookie = request.cookies.get(authn_cookie_key)

    if not authen(authn_cookie):
        return redirect('/login.html')

    return render_template('index.html')

@app.route("/login.html")
def login():
    return render_template('login.html')

@app.route("/register.php")
def register_api():
    username: str = request.args.get("username")
    password: str = request.args.get("password")
    target = os.path.join(user_dir,username)
    if not os.path.exists(target): 
        with open(target,'w') as f:
            f.writelines(json.dumps({'username': username,'password':password}))
        return {"result":"success"}
    else:
        return {"result":"fail", "reason": "username has been registered"}


@app.route("/attr.php")
def attr_api():
    school: str = request.args.get("school")
    username: str = request.args.get("username")
    identity: str = request.args.get("id")

    rp = open(uid_loc, 'r')
    uid = rp.read()
    rp.close()

    data = school+username+identity+uid
    re_id = hashlib.md5(data.encode(encoding='UTF-8')).hexdigest()
    attr = [school, username, identity, re_id]
    wp = open(uid_loc, 'w')
    wp.write(str(int(uid)+1))
    wp.close()

    (sk,pk) = do_sk(attr)
    
    user = ""
    with open(os.path.join(user_dir,username),"r") as f:
        user = f.readline()
    user = json.loads(user)
    user["sk"] = json.loads(sk)
    user["pk"] = json.loads(pk)
    user["id"] = re_id
    with open(os.path.join(user_dir,username),"w") as f:
        f.writelines(json.dumps(user))

    return {"result":"success","sk":sk,"pk":pk,"id":re_id}
    

def do_sk(attributes: list):
    # return ("","")
    group = PairingGroup('SS512')
    cp_abe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cp_abe, group)
    pk_fp = open(pk_loc, 'r')
    r_pk = pk_fp.read()
    re_pk = json.loads(r_pk)
    pk_fp.close()
    re_pk['g'] = group.deserialize(re_pk['g'].encode('utf-8'))
    re_pk['g2'] = group.deserialize(re_pk['g2'].encode('utf-8'))
    re_pk['h'] = group.deserialize(re_pk['h'].encode('utf-8'))
    re_pk['f'] = group.deserialize(re_pk['f'].encode('utf-8'))
    re_pk['e_gg_alpha'] = group.deserialize(re_pk['e_gg_alpha'].encode('utf-8'))

    sk_fp = open(msk_loc, 'r')
    r_msk = sk_fp.read()
    msk = json.loads(r_msk)
    sk_fp.close()
    msk['beta'] = group.deserialize(msk['beta'].encode('utf-8'))
    msk['g2_alpha'] = group.deserialize(msk['g2_alpha'].encode('utf-8'))

    usk = hyb_abe.keygen(re_pk, msk, attributes)
    usk['D'] = group.serialize(usk['D']).decode('utf-8')
    for i in usk['Dj']:
        usk['Dj'][i] = group.serialize(usk['Dj'][i]).decode('utf-8')

    for j in usk['Djp']:
        usk['Djp'][j] = group.serialize(usk['Djp'][j]).decode('utf-8')

    usk = json.dumps(usk)
    return usk, r_pk

@app.route("/login.php")
def login_api():
    username: str = request.args.get("username")
    password: str = request.args.get("password")
    if username == "":
        return {"result":"failed","reason":"please input password"}
    target = os.path.join(user_dir,username)
    if os.path.exists(target):
        with open(target,'r') as f:
            res = json.loads(f.readline())
            if res.get("password")== password:
                resp = make_response({"result":"success"})
                resp.set_cookie(authn_cookie_key, json.dumps({"username": username,"password":hashlib.md5(password.encode(encoding='UTF-8')).hexdigest()}),max_age=3600)
                return resp
    else:
        return {"result":"failed","reason":"user has not been registered"}

key_cfile = "cfile"
key_attr = "attr"
key_suffix = "suffix"

@app.route("/show.php")
def show_api():
    res = []
    for root, dirs, _ in os.walk(resources_dir,topdown=False):
        for directory in dirs:
            target = os.path.join(root,directory) 
            cfile_loc = os.path.join(target,key_cfile)
            attr_loc = os.path.join(target,key_attr)
            suffix_loc = os.path.join(target,key_suffix)
            attr = ""
            suffix = ""
            with open(attr_loc,'r') as f:
                attr = f.readline()
            with open(suffix_loc,'r') as f:
                suffix = f.readline()
            res.append({"name":directory+"."+suffix,"attr":attr,"path":cfile_loc})

    return {"num":len(res),"filename":res}

@app.route("/upload.php",methods=["POST"])
def upload_api():
    attr = request.form.get(key_attr)
    if attr == "":
        return "<script>alert('Error: attr error')</script>"
    
    # check if the post request has the file part
    if 'uploadfile' not in request.files:
        return "<script>alert('Error: no file found')</script>"
    file = request.files['uploadfile']
    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        return "<script>alert('Error: not select file')</script>"
    if file :
        filename = file.filename.split('.')[0]
        suffix = file.filename.split('.')[1]
        resourcepath = os.path.join(resources_dir,filename)
        num = 0
        filepath = resourcepath
        while os.path.isdir(filepath):
            num+=1
            filepath = resourcepath + str(num)
        
        os.mkdir(filepath)
        cfilepath = os.path.join(filepath,key_cfile)
        with open(cfilepath,'w'):
            pass
        suffixpath = os.path.join(filepath,key_suffix)
        with open(suffixpath,'w') as f:
            f.writelines(suffix)
        
        file.save(os.path.join(resources_dir, file.filename))
        with open(os.path.join(filepath,key_attr),'w') as f:
            f.writelines(attr)
        
        encrypt(os.path.join(resources_dir,file.filename),cfilepath,attr)
        os.remove(os.path.join(resources_dir,file.filename))

        return redirect('/index.html')
    
def encrypt(filepath, cfilepath, attr):
    rp = open(filepath, 'rb')
    data = rp.read()
    rp.close()

    group = PairingGroup('SS512')
    cp_abe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cp_abe, group)
    pk_fp = open(pk_loc, 'r')
    re_pk = json.loads(pk_fp.read())
    pk_fp.close()
    re_pk['g'] = group.deserialize(re_pk['g'].encode('utf-8'))
    re_pk['g2'] = group.deserialize(re_pk['g2'].encode('utf-8'))
    re_pk['h'] = group.deserialize(re_pk['h'].encode('utf-8'))
    re_pk['f'] = group.deserialize(re_pk['f'].encode('utf-8'))
    re_pk['e_gg_alpha'] = group.deserialize(re_pk['e_gg_alpha'].encode('utf-8'))

    ciphertext = hyb_abe.encrypt(re_pk, data, attr)
    ciphertext["c1"]["C"] = group.serialize(ciphertext["c1"]["C"]).decode('utf-8')
    for key in ciphertext["c1"]["Cy"]:
        ciphertext["c1"]["Cy"][key] = group.serialize(ciphertext["c1"]["Cy"][key]).decode('utf-8')
    ciphertext["c1"]["C_tilde"] = group.serialize(ciphertext["c1"]["C_tilde"]).decode('utf-8')
    for key in ciphertext["c1"]["Cyp"]:
        ciphertext["c1"]["Cyp"][key] = group.serialize(ciphertext["c1"]["Cyp"][key]).decode('utf-8')

    ciphertext = json.dumps(ciphertext)
    with open(cfilepath, 'w') as fp:
        fp.write(ciphertext)

@app.route("/resources/<string:name>/cfile")
def download_api(name):
    if name == '' :
        return {'result':'failed','reason':'file name is empty'} 

    authn_cookie = request.cookies.get(authn_cookie_key)
    res = authen(authn_cookie)
    if not res:
        return redirect('/login.html')
    user = res[1]
    target = os.path.join(resources_dir,name)
    suffix = ""
    with open(os.path.join(target,key_suffix),"r") as f:
        suffix = f.readline() 
    cfile = ""
    with open(os.path.join(target,key_cfile),"r") as f:
        cfile = f.readline()

    data = ""
    try:
        data = decrypto(cfile,user["pk"],user["sk"])
    except:
        abort(403)
    resp = Response(data)
    filename = name+"."+suffix
    resp.headers['Content-Type'] = mimetypes.guess_type(filename)
    resp.headers['Content-Disposition'] = 'attachment; filename={}'.format(filename.encode().decode('latin-1'))
    return resp

def decrypto(cfile,pk,sk):
    cipher = json.loads(cfile)

    group = PairingGroup('SS512')
    cp_abe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cp_abe, group)

    cipher["c1"]["C"] = group.deserialize(cipher["c1"]["C"].encode('utf-8'))
    for key in cipher["c1"]["Cy"]:
        cipher["c1"]["Cy"][key] = group.deserialize(cipher["c1"]["Cy"][key].encode('utf-8'))
    cipher["c1"]["C_tilde"] = group.deserialize(cipher["c1"]["C_tilde"].encode('utf-8'))
    for key in cipher["c1"]["Cyp"]:
        cipher["c1"]["Cyp"][key] = group.deserialize(cipher["c1"]["Cyp"][key].encode('utf-8'))

    re_pk = pk
    re_pk['g'] = group.deserialize(re_pk['g'].encode('utf-8'))
    re_pk['g2'] = group.deserialize(re_pk['g2'].encode('utf-8'))
    re_pk['h'] = group.deserialize(re_pk['h'].encode('utf-8'))
    re_pk['f'] = group.deserialize(re_pk['f'].encode('utf-8'))
    re_pk['e_gg_alpha'] = group.deserialize(re_pk['e_gg_alpha'].encode('utf-8'))

    sk['D'] = group.deserialize(sk['D'].encode('utf-8'))
    for i in sk['Dj']:
        sk['Dj'][i] = group.deserialize(sk['Dj'][i].encode('utf-8'))

    for j in sk['Djp']:
        sk['Djp'][j] = group.deserialize(sk['Djp'][j].encode('utf-8'))

    msg = hyb_abe.decrypt(re_pk, sk, cipher)
    return msg.decode('utf-8')

@app.route("/logout")
def logout_api():
    resp = make_response(redirect("/login.html"))
    resp.delete_cookie(authn_cookie_key)
    return resp

@app.route("/delete/resources/<string:name>")
def delete_resource_api(name):
    name = name.split(".")[0]
    try:
        shutil.rmtree(os.path.join(resources_dir,name))
    except:
        pass
    return redirect(location='/index.html')