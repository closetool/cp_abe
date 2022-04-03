import base64
import json
import os
from flask import Flask, render_template, request

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from json import dumps, loads
import sys
import hashlib

app = Flask(__name__,template_folder='static',static_folder='static',static_url_path='/static')

user_dir = './users'
uid_loc = './uid.txt'

pk_loc = './pk.json'
msk_loc = './msk.json'

def check_exists(dirs):
    for dir in dirs:
        if not os.path.exists(dir):
            os.makedirs(dir)

check_exists([user_dir,uid_loc])


@app.route("/")
def home():
    return render_template('index.html')

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/register.php")
def register_api():
    username: str = request.args.get("username")
    password: str = request.args.get("password")
    target = os.path.join(user_dir,username)
    if not os.path.exists(target): 
        with open(target,'w') as f:
            f.readline(json.dumps({'username': username,'password':password}))
    else:
        return {"result":"fail", "reason": "username has been registered"}


@app.route("/attr.php")
def attr():
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

    return {"sk":sk,"pk":pk,"rid":re_id}
    

def do_sk(attributes: list):
    group = PairingGroup('SS512')
    cp_abe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cp_abe, group)
    pk_fp = open(pk_loc, 'r')
    r_pk = pk_fp.read()
    re_pk = loads(r_pk)
    pk_fp.close()
    re_pk['g'] = group.deserialize(re_pk['g'].encode('utf-8'))
    re_pk['g2'] = group.deserialize(re_pk['g2'].encode('utf-8'))
    re_pk['h'] = group.deserialize(re_pk['h'].encode('utf-8'))
    re_pk['f'] = group.deserialize(re_pk['f'].encode('utf-8'))
    re_pk['e_gg_alpha'] = group.deserialize(re_pk['e_gg_alpha'].encode('utf-8'))

    sk_fp = open(msk_loc, 'r')
    r_msk = sk_fp.read()
    msk = loads(r_msk)
    sk_fp.close()
    msk['beta'] = group.deserialize(msk['beta'].encode('utf-8'))
    msk['g2_alpha'] = group.deserialize(msk['g2_alpha'].encode('utf-8'))

    usk = hyb_abe.keygen(re_pk, msk, attributes)
    usk['D'] = group.serialize(usk['D']).decode('utf-8')
    for i in usk['Dj']:
        usk['Dj'][i] = group.serialize(usk['Dj'][i]).decode('utf-8')

    for j in usk['Djp']:
        usk['Djp'][j] = group.serialize(usk['Djp'][j]).decode('utf-8')

    usk = dumps(usk)
    return usk, r_pk