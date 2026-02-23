from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_socketio import SocketIO, emit
import threading, time, os, json, random, io
from datetime import datetime
from functools import wraps
from rules import is_suspicious

app = Flask(__name__)
app.secret_key = 'network_analyzer_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── Users Storage ────────────────────────────────────────────────────────────
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    default = {"admin": "admin123"}
    save_users(default)
    return default

def save_users(u):
    with open(USERS_FILE, 'w') as f:
        json.dump(u, f, indent=2)

# ─── Auth ─────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── Global State ─────────────────────────────────────────────────────────────
capture_state = {
    "running": False, "packets": [],
    "stats": {"total":0,"tcp":0,"udp":0,"icmp":0,"other":0,"suspicious":0,"bytes":0,"start_time":None}
}
capture_thread = None

DEMO_IPS_LOCAL    = ["192.168.1.1","192.168.1.10","192.168.1.20","10.0.0.1"]
DEMO_IPS_EXT      = ["8.8.8.8","142.250.74.46","93.184.216.34","1.1.1.1","104.21.10.1"]
DEMO_PROTOS       = ["TCP","UDP","ICMP"]
DEMO_PORTS_NORMAL = [80,443,53,8443]
DEMO_PORTS_SUSP   = [22,23,3389,445,4444]

def demo_capture():
    pkt_id = capture_state["stats"]["total"]
    while capture_state["running"]:
        time.sleep(random.uniform(0.1, 0.5))
        pkt_id += 1
        proto = random.choice(DEMO_PROTOS)
        susp_trigger = random.random() < 0.15
        dport  = random.choice(DEMO_PORTS_SUSP if susp_trigger else DEMO_PORTS_NORMAL)
        sport  = random.randint(1024, 65535)
        length = random.randint(40, 1500)
        flags  = random.choice(["S","A","PA","FA"]) if proto == "TCP" else None
        info   = {
            "id": pkt_id,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": random.choice(DEMO_IPS_LOCAL),
            "dst": random.choice(DEMO_IPS_EXT),
            "proto": proto,
            "sport": sport if proto != "ICMP" else None,
            "dport": dport if proto != "ICMP" else None,
            "flags": flags, "length": length,
            "suspicious": False, "reasons": []
        }
        reasons = is_suspicious(info)
        if reasons:
            info["suspicious"] = True; info["reasons"] = reasons
            capture_state["stats"]["suspicious"] += 1
        capture_state["stats"]["total"]  += 1
        capture_state["stats"]["bytes"]  += length
        if proto == "TCP":    capture_state["stats"]["tcp"]  += 1
        elif proto == "UDP":  capture_state["stats"]["udp"]  += 1
        elif proto == "ICMP": capture_state["stats"]["icmp"] += 1
        else:                 capture_state["stats"]["other"]+= 1
        capture_state["packets"].append(info)
        socketio.emit("new_packet", info)
        socketio.emit("stats_update", capture_state["stats"])

def try_real_capture(iface=None):
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
        if iface is None: iface = conf.iface
        def process_packet(pkt):
            if not capture_state["running"] or IP not in pkt: return
            info = {
                "id": capture_state["stats"]["total"]+1,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": pkt[IP].src, "dst": pkt[IP].dst,
                "proto":"OTHER","sport":None,"dport":None,"flags":None,
                "length":len(pkt),"suspicious":False,"reasons":[]
            }
            if TCP in pkt:
                info.update({"proto":"TCP","sport":pkt[TCP].sport,"dport":pkt[TCP].dport,"flags":str(pkt[TCP].flags)})
                capture_state["stats"]["tcp"] += 1
            elif UDP in pkt:
                info.update({"proto":"UDP","sport":pkt[UDP].sport,"dport":pkt[UDP].dport})
                capture_state["stats"]["udp"] += 1
            elif ICMP in pkt:
                info["proto"]="ICMP"; capture_state["stats"]["icmp"] += 1
            else:
                capture_state["stats"]["other"] += 1
            reasons = is_suspicious(info)
            if reasons:
                info["suspicious"]=True; info["reasons"]=reasons
                capture_state["stats"]["suspicious"] += 1
            capture_state["stats"]["total"] += 1
            capture_state["stats"]["bytes"] += info["length"]
            capture_state["packets"].append(info)
            socketio.emit("new_packet", info)
            socketio.emit("stats_update", capture_state["stats"])
        sniff(iface=iface, prn=process_packet,
              stop_filter=lambda x: not capture_state["running"], store=False)
    except Exception:
        demo_capture()

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'logged_in' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        users = load_users()
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if users.get(u) == p:
            session['logged_in'] = True; session['username'] = u
            return redirect(url_for('dashboard'))
        error = "Identifiants incorrects"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
@login_required
def register():
    error = success = None
    if request.method == 'POST':
        users = load_users()
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        c = request.form.get('confirm','')
        if not u or not p:
            error = "Tous les champs sont obligatoires"
        elif len(u) < 3:
            error = "Nom d'utilisateur : minimum 3 caractères"
        elif len(p) < 6:
            error = "Mot de passe : minimum 6 caractères"
        elif p != c:
            error = "Les mots de passe ne correspondent pas"
        elif u in users:
            error = f"L'utilisateur '{u}' existe déjà"
        else:
            users[u] = p; save_users(users)
            success = f"Compte '{u}' créé avec succès !"
    users_list = list(load_users().keys())
    return render_template('register.html', error=error, success=success, users_list=users_list)

@app.route('/api/user/delete', methods=['POST'])
@login_required
def delete_user():
    data = request.json or {}
    username = data.get('username','')
    if username == 'admin':
        return jsonify({"error": "Impossible de supprimer le compte admin"}), 400
    if username == session.get('username'):
        return jsonify({"error": "Impossible de supprimer votre propre compte"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "Utilisateur introuvable"}), 404
    del users[username]; save_users(users)
    return jsonify({"success": True})

@app.route('/dashboard') 
@login_required
def dashboard(): return render_template('dashboard.html')

@app.route('/capture')
@login_required
def capture(): return render_template('capture.html')

@app.route('/pcap')
@login_required
def pcap(): return render_template('pcap.html')

@app.route('/reports')
@login_required
def reports(): return render_template('reports.html')

# ─── API Capture ──────────────────────────────────────────────────────────────
@app.route('/api/capture/start', methods=['POST'])
@login_required
def start_capture():
    global capture_thread
    if capture_state["running"]:
        return jsonify({"status":"already_running"})
    capture_state["running"] = True
    capture_state["packets"] = []
    capture_state["stats"] = {"total":0,"tcp":0,"udp":0,"icmp":0,"other":0,"suspicious":0,"bytes":0,
                               "start_time":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    iface = (request.json or {}).get("iface")
    capture_thread = threading.Thread(target=try_real_capture, args=(iface,), daemon=True)
    capture_thread.start()
    return jsonify({"status":"started"})

@app.route('/api/capture/stop', methods=['POST'])
@login_required
def stop_capture():
    capture_state["running"] = False
    return jsonify({"status":"stopped","stats":capture_state["stats"]})

@app.route('/api/capture/status')
@login_required
def capture_status():
    return jsonify({"running":capture_state["running"],"stats":capture_state["stats"],
                    "packets_count":len(capture_state["packets"])})

@app.route('/api/packets')
@login_required
def get_packets():
    page    = int(request.args.get('page',1))
    per_page= int(request.args.get('per_page',50))
    fp      = request.args.get('proto','')
    fi      = request.args.get('ip','')
    fs      = request.args.get('suspicious','')
    pkts = capture_state["packets"][:]
    if fp: pkts = [p for p in pkts if p['proto']==fp.upper()]
    if fi: pkts = [p for p in pkts if fi in p['src'] or fi in p['dst']]
    if fs=='true': pkts = [p for p in pkts if p['suspicious']]
    total = len(pkts); start=(page-1)*per_page
    return jsonify({"packets":pkts[start:start+per_page],"total":total,"page":page,
                    "pages":(total+per_page-1)//per_page})

@app.route('/api/interfaces')
@login_required
def get_interfaces():
    try:
        from scapy.all import get_if_list
        return jsonify({"interfaces":get_if_list()})
    except:
        return jsonify({"interfaces":["eth0","wlan0","lo"]})

# ─── API PCAP Upload ──────────────────────────────────────────────────────────
@app.route('/api/upload_pcap', methods=['POST'])
@login_required
def upload_pcap():
    if 'file' not in request.files: return jsonify({"error":"No file"}),400
    f = request.files['file']
    if not (f.filename.endswith('.pcap') or f.filename.endswith('.pcapng')):
        return jsonify({"error":"Format invalide"}),400
    filepath = os.path.join('uploads', f.filename)
    f.save(filepath)
    packets, stats = [], {"total":0,"tcp":0,"udp":0,"icmp":0,"other":0,"suspicious":0,"bytes":0}
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
        pkts = rdpcap(filepath)
        for i, pkt in enumerate(pkts):
            if IP not in pkt: continue
            info = {"id":i+1,
                    "timestamp":datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
                    "src":pkt[IP].src,"dst":pkt[IP].dst,"proto":"OTHER",
                    "sport":None,"dport":None,"flags":None,"length":len(pkt),"suspicious":False,"reasons":[]}
            if TCP in pkt:
                info.update({"proto":"TCP","sport":pkt[TCP].sport,"dport":pkt[TCP].dport,"flags":str(pkt[TCP].flags)})
                stats["tcp"]+=1
            elif UDP in pkt:
                info.update({"proto":"UDP","sport":pkt[UDP].sport,"dport":pkt[UDP].dport})
                stats["udp"]+=1
            elif ICMP in pkt:
                info["proto"]="ICMP"; stats["icmp"]+=1
            else: stats["other"]+=1
            reasons=is_suspicious(info)
            if reasons: info["suspicious"]=True; info["reasons"]=reasons; stats["suspicious"]+=1
            stats["total"]+=1; stats["bytes"]+=info["length"]
            packets.append(info)
    except Exception:
        for i in range(random.randint(80,150)):
            proto=random.choice(["TCP","UDP","ICMP"]); susp=random.random()<0.12
            dport=random.choice(DEMO_PORTS_SUSP if susp else DEMO_PORTS_NORMAL)
            info={"id":i+1,"timestamp":f"00:{i//60:02d}:{i%60:02d}.000",
                  "src":random.choice(DEMO_IPS_LOCAL),"dst":random.choice(DEMO_IPS_EXT),
                  "proto":proto,"sport":random.randint(1024,65535) if proto!="ICMP" else None,
                  "dport":dport if proto!="ICMP" else None,
                  "flags":random.choice(["S","A","PA"]) if proto=="TCP" else None,
                  "length":random.randint(40,1500),"suspicious":False,"reasons":[]}
            reasons=is_suspicious(info)
            if reasons: info["suspicious"]=True; info["reasons"]=reasons; stats["suspicious"]+=1
            stats["total"]+=1; stats["bytes"]+=info["length"]
            if proto=="TCP": stats["tcp"]+=1
            elif proto=="UDP": stats["udp"]+=1
            elif proto=="ICMP": stats["icmp"]+=1
            packets.append(info)
    return jsonify({"packets":packets,"stats":stats})

# ─── API Report ───────────────────────────────────────────────────────────────
def build_report(packets, stats):
    r = {"generated_at":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         "generated_by":session.get('username','admin'),
         "stats":stats,"top_ips_src":{},"top_ips_dst":{},"top_ports":{},"suspicious_packets":[]}
    for p in packets:
        src=p.get("src",""); dst=p.get("dst",""); dp=p.get("dport")
        r["top_ips_src"][src]=r["top_ips_src"].get(src,0)+1
        r["top_ips_dst"][dst]=r["top_ips_dst"].get(dst,0)+1
        if dp: r["top_ports"][str(dp)]=r["top_ports"].get(str(dp),0)+1
        if p.get("suspicious"): r["suspicious_packets"].append(p)
    r["top_ips_src"]=sorted(r["top_ips_src"].items(),key=lambda x:-x[1])[:10]
    r["top_ips_dst"]=sorted(r["top_ips_dst"].items(),key=lambda x:-x[1])[:10]
    r["top_ports"]  =sorted(r["top_ports"].items(),  key=lambda x:-x[1])[:10]
    return r

@app.route('/api/report/generate', methods=['POST'])
@login_required
def generate_report():
    data=request.json or {}
    r=build_report(data.get("packets",capture_state["packets"]),data.get("stats",capture_state["stats"]))
    path=f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(path,'w') as f: json.dump(r,f,indent=2)
    return jsonify(r)

@app.route('/api/report/pdf', methods=['POST'])
@login_required
def generate_pdf():
    data=request.json or {}
    r=build_report(data.get("packets",capture_state["packets"]),data.get("stats",capture_state["stats"]))
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.units import cm

        buf=io.BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=2*cm,rightMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)
        DARK=colors.HexColor('#040810'); ACCENT=colors.HexColor('#00d4ff')
        DANGER=colors.HexColor('#ff3366'); WARN=colors.HexColor('#ffaa00')
        MUTED=colors.HexColor('#4a7a96'); LIGHT=colors.HexColor('#c8e6f5')
        BG1=colors.HexColor('#080f1a'); BG2=colors.HexColor('#0c1624')

        def sty(name,**kw): return ParagraphStyle(name,**kw)
        title_s=sty('T',fontName='Helvetica-Bold',fontSize=22,textColor=ACCENT,spaceAfter=4)
        sub_s  =sty('S',fontName='Helvetica',fontSize=9,textColor=MUTED,spaceAfter=20)
        h2_s   =sty('H',fontName='Helvetica-Bold',fontSize=13,textColor=ACCENT,spaceBefore=16,spaceAfter=8)
        body_s =sty('B',fontName='Helvetica',fontSize=9,textColor=LIGHT,spaceAfter=6)

        def tbl(data,cols,hdr_color=ACCENT,hdr_text=colors.black):
            t=Table(data,colWidths=cols)
            t.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),hdr_color),('TEXTCOLOR',(0,0),(-1,0),hdr_text),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),8),
                ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#0d2137')),
                ('BACKGROUND',(0,1),(-1,-1),BG1),('TEXTCOLOR',(0,1),(-1,-1),LIGHT),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG1,BG2]),('PADDING',(0,0),(-1,-1),5),
            ]))
            return t

        stats=r["stats"]; total=stats.get('total',0); susp=stats.get('suspicious',0)
        byt=stats.get('bytes',0)
        byts=f"{byt/1048576:.2f} MB" if byt>=1048576 else f"{byt/1024:.1f} KB" if byt>=1024 else f"{byt} B"

        story=[]
        story.append(Paragraph("NetWatch — Rapport d'Analyse Réseau",title_s))
        story.append(Paragraph(f"Généré le {r['generated_at']} par {r['generated_by']}",sub_s))
        story.append(HRFlowable(width="100%",thickness=1,color=ACCENT))
        story.append(Spacer(1,0.4*cm))

        story.append(Paragraph("Résumé",h2_s))
        story.append(tbl([["Métrique","Valeur"],
            ["Paquets totaux",str(total)],["Volume",byts],
            ["Suspects",str(susp)],["Taux",f"{(susp/total*100):.1f}%" if total else "0%"],
            ["TCP",str(stats.get('tcp',0))],["UDP",str(stats.get('udp',0))],
            ["ICMP",str(stats.get('icmp',0))],["Démarrage",stats.get('start_time','N/A')]],
            [8*cm,8*cm]))
        story.append(Spacer(1,0.5*cm))

        if r['top_ips_src']:
            story.append(Paragraph("Top IP Sources",h2_s))
            story.append(tbl([["#","IP Source","Paquets"]]+[[str(i+1),ip,str(c)] for i,(ip,c) in enumerate(r['top_ips_src'])],
                [1.5*cm,10*cm,5*cm]))
            story.append(Spacer(1,0.4*cm))

        if r['top_ips_dst']:
            story.append(Paragraph("Top IP Destinations",h2_s))
            story.append(tbl([["#","IP Destination","Paquets"]]+[[str(i+1),ip,str(c)] for i,(ip,c) in enumerate(r['top_ips_dst'])],
                [1.5*cm,10*cm,5*cm]))
            story.append(Spacer(1,0.4*cm))

        if r['top_ports']:
            story.append(Paragraph("Top Ports",h2_s))
            story.append(tbl([["#","Port","Paquets"]]+[[str(i+1),f":{p}",str(c)] for i,(p,c) in enumerate(r['top_ports'])],
                [1.5*cm,10*cm,5*cm],hdr_color=WARN,hdr_text=DARK))
            story.append(Spacer(1,0.4*cm))

        story.append(Paragraph("Connexions Suspectes",h2_s))
        if r['suspicious_packets']:
            rows=[["#","Source","Destination","Proto","Port","Raison"]]
            for i,p in enumerate(r['suspicious_packets'][:30],1):
                rows.append([str(i),p.get('src',''),p.get('dst',''),p.get('proto',''),
                             str(p.get('dport','—')),"; ".join(p.get('reasons',[]))[:45]])
            t=Table(rows,colWidths=[0.8*cm,3.5*cm,3.5*cm,1.5*cm,1.5*cm,6*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),DANGER),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),7),
                ('GRID',(0,0),(-1,-1),0.3,colors.HexColor('#0d2137')),
                ('BACKGROUND',(0,1),(-1,-1),colors.HexColor('#1a0810')),
                ('TEXTCOLOR',(0,1),(-1,-1),colors.HexColor('#ffb3c1')),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#1a0810'),colors.HexColor('#200d14')]),
                ('PADDING',(0,0),(-1,-1),4),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("✓ Aucune connexion suspecte détectée.",body_s))

        doc.build(story); buf.seek(0)
        fname=f"netwatch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(buf,mimetype='application/pdf',as_attachment=True,download_name=fname)
    except ImportError:
        return jsonify({"error":"Installez reportlab : pip install reportlab"}),500

if __name__ == '__main__':
    os.makedirs('uploads',exist_ok=True); os.makedirs('reports',exist_ok=True)
    socketio.run(app,debug=True,host='0.0.0.0',port=5000)
