import os
import sys
import uuid
import json
import base64
import sqlite3
import subprocess
import time
import threading
import socket
import struct
import urllib.parse
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session

try:
    import telebot
except ImportError:
    telebot = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vega-rail-secret-key-change-me")

ADMIN_USERNAME = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "admin")

BRAND_BOLD = "𝗩𝗘𝗚𝗔"  # فرم بولد یونیکد نام برند در remark کانفیگ‌ها

XRAY_PORT = 10000
TROJAN_PORT = 10001
VMESS_PORT = 10002
XRAY_API_PORT = 10085
FLASK_PORT = 5000

DB_PATH = "users.db"
XRAY_CONFIG_PATH = "xray_config.json"
NGINX_CONFIG_PATH = "nginx.conf"

ONLINE_USERS = {}
ONLINE_THRESHOLD = 90

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            uuid TEXT UNIQUE NOT NULL,
            quota_gb REAL DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            expire_days INTEGER DEFAULT 30,
            created_at TEXT,
            enabled INTEGER DEFAULT 1
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    conn.commit()
    conn.close()

def get_setting(key, default=""):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default

def set_setting(key, value):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print("Error saving setting:", e)
        return False

def get_admin_credentials():
    env_user = os.environ.get("ADMIN_USER")
    env_pass = os.environ.get("ADMIN_PASS")

    if env_user is not None and env_pass is not None:
        return env_user, env_pass

    settings_file = "panel_settings.json"

    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            username = data.get("username", "admin")
            password = data.get("password", "admin")

            return username, password

        except Exception:
            pass

    return "admin", "admin"

def save_admin_credentials(username, password):
    settings_file = "panel_settings.json"

    data = {
        "username": username,
        "password": password
    }

    with open(settings_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_all_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def is_user_active(user):
    """بررسی فعال بودن کاربر بر اساس ترافیک، زمان و وضعیت کلی"""
    if user["enabled"] == 0:
        return False, "disabled"

    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        if elapsed_days >= user["expire_days"]:
            return False, "expired"
    except Exception:
        pass

    used_gb = user["used_bytes"] / (1024 ** 3)
    if user["quota_gb"] > 0 and used_gb >= user["quota_gb"]:
        return False, "limit_exceeded"

    return True, "active"

def enrich_user(u):
    try:
        created_dt = datetime.fromisoformat(u["created_at"])
        elapsed_days = (datetime.now() - created_dt).days
        days_left = max(0, u["expire_days"] - elapsed_days)
    except Exception:
        days_left = u["expire_days"]

    used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
    quota_gb = round(float(u["quota_gb"]), 2)

    if quota_gb > 0:
        percent = min(100, round((used_gb / quota_gb) * 100, 1))
    else:
        percent = 0

    active_state, reason = is_user_active(u)

    u["used_gb"] = used_gb
    u["days_left"] = days_left
    u["percent"] = percent
    u["is_expired"] = days_left <= 0 or reason == "expired"
    u["is_limit_exceeded"] = reason == "limit_exceeded"
    u["is_active"] = active_state
    u["created_date"] = u["created_at"][:10] if u.get("created_at") else ""
    u["is_online"] = is_user_online(u["name"])

    return u

def is_user_online(name):
    last_seen = ONLINE_USERS.get(name, 0)
    return (time.time() - last_seen) < ONLINE_THRESHOLD

def build_xray_config():
    users = get_all_users()

    vless_clients = []
    trojan_clients = []
    vmess_clients = []

    for u in users:
        # فقط کاربرانی که واقعاً فعال هستند داخل کانفیگ Xray ریخته می‌شوند
        active, _ = is_user_active(u)
        if not active:
            continue

        vless_clients.append({"id": u["uuid"], "email": u["name"], "level": 0})
        # در تروجان رمز عبور همان UUID کاربر است تا همه پروتکل‌ها یک هویت داشته باشند
        trojan_clients.append({"password": u["uuid"], "email": u["name"], "level": 0})
        vmess_clients.append({"id": u["uuid"], "email": u["name"], "level": 0})

    if not vless_clients:
        fallback_id = str(uuid.uuid4())
        vless_clients.append({"id": fallback_id, "email": "default_user", "level": 0})
        trojan_clients.append({"password": fallback_id, "email": "default_user", "level": 0})
        vmess_clients.append({"id": fallback_id, "email": "default_user", "level": 0})

    config = {
        "log": {
            "loglevel": "warning"
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        },
        "inbounds": [
            {
                "tag": "api",
                "port": XRAY_API_PORT,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            },
            {
                "tag": "vless-in",
                "port": XRAY_PORT,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": vless_clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/ws"
                    }
                }
            },
            {
                "tag": "trojan-in",
                "port": TROJAN_PORT,
                "listen": "127.0.0.1",
                "protocol": "trojan",
                "settings": {
                    "clients": trojan_clients
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/tr"
                    }
                }
            },
            {
                "tag": "vmess-in",
                "port": VMESS_PORT,
                "listen": "127.0.0.1",
                "protocol": "vmess",
                "settings": {
                    "clients": vmess_clients
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {
                        "path": "/vm"
                    }
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                }
            ]
        }
    }

    with open(XRAY_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

def restart_xray():
    build_xray_config()
    try:
        subprocess.run(["pkill", "-9", "-f", "xray"], check=False)
        time.sleep(0.5)
    except Exception:
        pass

    try:
        xray_bin = "/usr/local/bin/xray/xray"
        if not os.path.exists(xray_bin):
            xray_bin = "xray"

        subprocess.Popen(
            [xray_bin, "run", "-c", XRAY_CONFIG_PATH],
            stdout=sys.stdout,
            stderr=sys.stderr
        )
    except Exception as e:
        print("Xray start error:", e)

def xray_query_stats():
    stats = {}
    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

    try:
        result = subprocess.run(
            [
                xray_bin,
                "api",
                "statsquery",
                f"--server=127.0.0.1:{XRAY_API_PORT}",
                "-pattern=user>>>",
                "-reset=true"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return stats

        data = json.loads(result.stdout)
        stat_list = data.get("stat", [])

        for item in stat_list:
            name = item.get("name", "")
            value = int(item.get("value", 0))

            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user":
                user_email = parts[1]

                if user_email not in stats:
                    stats[user_email] = 0

                stats[user_email] += value

    except Exception:
        pass

    return stats

def xray_reset_user_stats(user_email):
    xray_bin = "/usr/local/bin/xray/xray"
    if not os.path.exists(xray_bin):
        xray_bin = "xray"

    try:
        for direction in ["uplink", "downlink"]:
            subprocess.run(
                [
                    xray_bin,
                    "api",
                    "statsquery",
                    f"--server=127.0.0.1:{XRAY_API_PORT}",
                    "-reset=true",
                    f"-pattern=user>>>{user_email}>>>traffic>>>{direction}"
                ],
                capture_output=True,
                timeout=3
            )
    except Exception:
        pass

PREVIOUS_STATS = {}

def stats_collector():
    global PREVIOUS_STATS

    while True:
        try:
            time.sleep(15)

            stats = xray_query_stats()

            if not stats:
                continue

            conn = get_db()
            c = conn.cursor()

            need_restart = False

            for user_email, total_bytes in stats.items():
                if total_bytes <= 0:
                    continue

                c.execute(
                    "UPDATE users SET used_bytes = used_bytes + ? WHERE name = ?",
                    (total_bytes, user_email)
                )

                ONLINE_USERS[user_email] = time.time()

                c.execute(
                    "SELECT id, quota_gb, used_bytes, enabled, created_at, expire_days FROM users WHERE name = ?",
                    (user_email,)
                )

                row = c.fetchone()

                if row and row["enabled"] == 1:
                    # دیگر کاربر را در دیتابیس کلاً غیرفعال نمی‌کنیم (تا سابسکریپشن قطع نشود)
                    # فقط وضعیت فعال بودن واقعی او را می‌سنجیم و در صورت لزوم Xray را ریستارت می‌کنیم تا قطع شود
                    active, reason = is_user_active(dict(row))
                    if not active:
                        need_restart = True
                        print(f"[QUOTA/TIME] User '{user_email}' is no longer active ({reason}). Disabling from Xray.")

            conn.commit()
            conn.close()

            if need_restart:
                restart_xray()

        except Exception as e:
            print("Stats collector error:", e)

def start_stats_collector():
    t = threading.Thread(target=stats_collector, daemon=True)
    t.start()

def start_nginx():
    port = os.environ.get("PORT", "8080")

    nginx_conf = f"""
pid /run/nginx.pid;
error_log /dev/stderr warn;
events {{
    worker_connections 1024;
}}
http {{
    access_log /dev/stdout;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    map $http_upgrade $connection_upgrade {{
        default upgrade;
        '' close;
    }}
    server {{
        listen {port};
        server_name _;
        location ~ ^/ws {{
            proxy_redirect off;
            rewrite ^/ws.*$ /ws break;
            proxy_pass http://127.0.0.1:{XRAY_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location ~ ^/tr {{
            proxy_redirect off;
            rewrite ^/tr.*$ /tr break;
            proxy_pass http://127.0.0.1:{TROJAN_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location ~ ^/vm {{
            proxy_redirect off;
            rewrite ^/vm.*$ /vm break;
            proxy_pass http://127.0.0.1:{VMESS_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }}
        location / {{
            proxy_pass http://127.0.0.1:{FLASK_PORT};
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }}
    }}
}}
"""

    with open(NGINX_CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(nginx_conf)

    try:
        subprocess.run(["pkill", "-9", "-f", "nginx"], check=False)
        time.sleep(0.3)
    except Exception:
        pass

    subprocess.Popen([
        "nginx",
        "-c",
        os.path.abspath(NGINX_CONFIG_PATH),
        "-g",
        "daemon off;"
    ])

def _enc(value):
    return urllib.parse.quote(str(value), safe="")


def _vless_link(uuid_str, host, port, path, remark, tls=True, alpn=None, fp=None):
    params = [f"path={_enc(path)}", "type=ws", f"host={host}"]
    if tls:
        params += ["security=tls", "encryption=none", "insecure=0", "allowInsecure=0", f"sni={host}"]
    else:
        params += ["security=none", "encryption=none"]
    if alpn:
        params.append(f"alpn={_enc(alpn)}")
    if fp:
        params.append(f"fp={fp}")
    return f"vless://{uuid_str}@{host}:{port}?" + "&".join(params) + f"#{_enc(remark)}"


def _trojan_link(uuid_str, host, port, path, remark, alpn=None, fp=None):
    params = [
        f"path={_enc(path)}", "type=ws", f"host={host}",
        "security=tls", f"sni={host}", "allowInsecure=0",
    ]
    if alpn:
        params.append(f"alpn={_enc(alpn)}")
    if fp:
        params.append(f"fp={fp}")
    return f"trojan://{uuid_str}@{host}:{port}?" + "&".join(params) + f"#{_enc(remark)}"


def _vmess_link(uuid_str, host, port, path, remark, alpn=None, fp=None):
    obj = {
        "v": "2",
        "ps": remark,
        "add": host,
        "port": str(port),
        "id": uuid_str,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": host,
        "path": path,
        "tls": "tls",
        "sni": host,
    }
    if alpn:
        obj["alpn"] = alpn
    if fp:
        obj["fp"] = fp
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode()


def make_all_configs(user, host):
    """۸ کانفیگ برای هر کاربر: ۴ عدد VLESS، ۲ عدد Trojan، ۲ عدد VMess.

    هر سه پروتکل سمت سرور inbound جدا دارند (XRAY_PORT / TROJAN_PORT / VMESS_PORT)
    و از طریق nginx روی مسیرهای /ws ، /tr و /vm به بیرون سرو می‌شوند.
    """
    u_uuid = user["uuid"]
    name = user["name"]

    def remark(number, label):
        return f"{label} | {BRAND_BOLD} | {number} | {name}"

    # (شماره، برچسب، تگ، نوع، پارامترها)
    plan = [
        (1, "کانفیـگ پرسرعـت", "VLESS · 443", "vless",
         {"port": 443, "path": f"/ws/{u_uuid}", "alpn": "http/1.1", "fp": "chrome"}),
        (2, "کانفیـگ پرسرعـت", "VLESS · ED2560", "vless",
         {"port": 443, "path": f"/ws/{u_uuid}?ed=2560", "alpn": "h2,http/1.1", "fp": "firefox"}),
        (3, "کانفیـگ پرسرعـت", "VLESS · ED2048", "vless",
         {"port": 443, "path": f"/ws/{u_uuid}?ed=2048", "alpn": "http/1.1", "fp": "edge"}),
        (4, "کانفیـگ پرسرعـت", "VLESS · RANDOM", "vless",
         {"port": 443, "path": f"/ws/{u_uuid}", "alpn": None, "fp": "random"}),
        (5, "کانفیـگ تروجان", "TROJAN · 443", "trojan",
         {"port": 443, "path": f"/tr/{u_uuid}", "alpn": "http/1.1", "fp": "chrome"}),
        (6, "کانفیـگ تروجان", "TROJAN · ED2048", "trojan",
         {"port": 443, "path": f"/tr/{u_uuid}?ed=2048", "alpn": "h2,http/1.1", "fp": "firefox"}),
        (7, "کانفیـگ وی‌ام‌اس", "VMESS · 443", "vmess",
         {"port": 443, "path": f"/vm/{u_uuid}", "alpn": "http/1.1", "fp": "chrome"}),
        (8, "کانفیـگ وی‌ام‌اس", "VMESS · ED2048", "vmess",
         {"port": 443, "path": f"/vm/{u_uuid}?ed=2048", "alpn": "h2,http/1.1", "fp": "firefox"}),
    ]

    desc = {
        "vless": "اتصال پایدار روی هسته VLESS با وب‌سوکت و TLS",
        "trojan": "اتصال روی پروتکل تروجان با وب‌سوکت و TLS، مناسب شبکه‌های سخت‌گیر",
        "vmess": "اتصال روی پروتکل VMess با وب‌سوکت و TLS، گزینه جایگزین",
    }

    configs = []
    for number, label, tag, kind, p in plan:
        text = remark(number, label)
        if kind == "vless":
            link = _vless_link(
                u_uuid, host, p["port"], p["path"], text,
                tls=p.get("tls", True), alpn=p["alpn"], fp=p["fp"],
            )
        elif kind == "trojan":
            link = _trojan_link(u_uuid, host, p["port"], p["path"], text, alpn=p["alpn"], fp=p["fp"])
        else:
            link = _vmess_link(u_uuid, host, p["port"], p["path"], text, alpn=p["alpn"], fp=p["fp"])

        configs.append({
            "title": f"{label} | {BRAND_BOLD} | {number}",
            "desc": desc[kind],
            "tag": tag,
            "protocol": kind,
            "config": link,
        })

    return configs


# نام قدیمی برای سازگاری با کدهای قبلی
make_all_vless_configs = make_all_configs


def make_fake_config(reason, user, host):
    """تولید کانکشن غیرفعال (نمایشی) جهت اطلاع‌رسانی به کاربر نهایی در نرم‌افزارش"""
    u_uuid = str(uuid.uuid4())
    name = user["name"]
    
    if reason == "limit_exceeded":
        remark = f"⛔️ Traffic Limit Exceeded | {name}"
        desc = "حجم ترافیک مجاز شما به اتمام رسیده است. جهت تمدید اقدام کنید."
    elif reason == "expired":
        remark = f"⛔️ Subscription Expired | {name}"
        desc = "زمان اشتراک شما به پایان رسیده است. جهت تمدید اقدام کنید."
    else:
        remark = f"⛔️ Service Disabled | {name}"
        desc = "سرویس شما توسط ادمین غیرفعال شده است."
        
    remark_encoded = urllib.parse.quote(remark)
    
    config_str = (
        f"vless://{u_uuid}@{host}:443"
        f"?path=%2Fws%2Fdummy"
        f"&security=tls"
        f"&encryption=none"
        f"&host={host}"
        f"&fp=chrome"
        f"&type=ws"
        f"&sni={host}"
        f"#{remark_encoded}"
    )
    return [{
        "title": remark,
        "desc": desc,
        "tag": "Alert",
        "config": config_str
    }]

def get_subscription_header(user):
    """تولید هدر استاندارد مانیتورینگ حجم برای نمایش بالای نرم‌افزار کاربر"""
    used = int(user["used_bytes"])
    total = int(float(user["quota_gb"]) * (1024 ** 3))
    try:
        created_dt = datetime.fromisoformat(user["created_at"])
        expire_dt = created_dt + timedelta(days=int(user["expire_days"]))
        expire_ts = int(expire_dt.timestamp())
    except Exception:
        expire_ts = 0
    return f"upload=0; download={used}; total={total}; expire={expire_ts}"

@app.route("/")
def home():
    if "admin" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        current_username, current_password = get_admin_credentials()

        if username == current_username and password == current_password:
            session["admin"] = True
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="نام کاربری یا رمز عبور اشتباه است!")

    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "admin" not in session:
        return redirect(url_for("login"))

    users = get_all_users()

    total_gb = sum(u["quota_gb"] for u in users)
    total_used = sum(u["used_bytes"] for u in users) / (1024 ** 3)
    active_count = sum(1 for u in users if is_user_active(u)[0])

    return render_template(
        "dashboard.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2)
    )

@app.route("/users")
def users_page():
    if "admin" not in session:
        return redirect(url_for("login"))

    raw_users = get_all_users()
    users = [enrich_user(u) for u in raw_users]

    total_gb = sum(u["quota_gb"] for u in raw_users)
    total_used = sum(u["used_bytes"] for u in raw_users) / (1024 ** 3)
    active_count = sum(1 for u in users if u["is_active"])
    disabled_count = sum(1 for u in users if u["enabled"] == 0)
    expired_count = sum(1 for u in users if u["is_expired"] or u["is_limit_exceeded"])
    online_count = sum(1 for u in users if u["is_online"])

    return render_template(
        "users.html",
        users=users,
        total_users=len(users),
        active_users=active_count,
        disabled_users=disabled_count,
        expired_users=expired_count,
        online_users=online_count,
        total_gb=round(total_gb, 2),
        total_used=round(total_used, 2)
    )

@app.route("/api/online_users")
def api_online_users():
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    raw_users = get_all_users()
    online = []

    for u in raw_users:
        if is_user_online(u["name"]):
            last_seen = ONLINE_USERS.get(u["name"], 0)
            seconds_ago = int(time.time() - last_seen)

            online.append({
                "id": u["id"],
                "name": u["name"],
                "used_gb": round(u["used_bytes"] / (1024 ** 3), 2),
                "quota_gb": u["quota_gb"],
                "seconds_ago": seconds_ago
            })

    return jsonify({
        "status": "success",
        "count": len(online),
        "users": online
    })

@app.route("/settings")
def settings():
    if "admin" not in session:
        return redirect(url_for("login"))

    username, _ = get_admin_credentials()
    tg_token = get_setting("telegram_token", "")
    tg_admin_id = get_setting("telegram_admin_id", "")

    return render_template(
        "settings.html",
        current_username=username,
        telegram_token=tg_token,
        telegram_admin_id=tg_admin_id
    )

@app.route("/api/settings", methods=["POST"])
def update_settings():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    if action == "telegram":
        tg_token = data.get("telegram_token", "").strip()
        tg_admin_id = data.get("telegram_admin_id", "").strip()

        try:
            set_setting("telegram_token", tg_token)
            set_setting("telegram_admin_id", tg_admin_id)
            return jsonify({"status": "success", "message": "تنظیمات ربات تلگرام با موفقیت ثبت شد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == "security":
        new_username = data.get("username", "").strip()
        new_password = data.get("password", "")
        current_password = data.get("current_password", "")

        if not new_username:
            return jsonify({"status": "error", "message": "نام کاربری جدید الزامی است"}), 400

        if not new_password:
            return jsonify({"status": "error", "message": "رمز عبور جدید الزامی است"}), 400

        username, password = get_admin_credentials()

        if current_password != password:
            return jsonify({"status": "error", "message": "رمز عبور فعلی اشتباه است"}), 400

        if len(new_username) < 3:
            return jsonify({"status": "error", "message": "نام کاربری حداقل باید ۳ کاراکتر باشد"}), 400

        if len(new_password) < 4:
            return jsonify({"status": "error", "message": "رمز عبور حداقل باید ۴ کاراکتر باشد"}), 400

        try:
            save_admin_credentials(new_username, new_password)
            session.pop("admin", None)
            return jsonify({"status": "success", "message": "اطلاعات ورود تغییر کرد"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "error", "message": "درخواست نامعتبر"}), 400

@app.route("/api/add_user", methods=["POST"])
def add_user():
    if "admin" not in session:
        return jsonify({"status": "error", "message": "دسترسی غیرمجاز"}), 401

    data = request.json or {}

    name = data.get("name", "").strip()

    try:
        quota = float(data.get("quota", 30))
        days = int(data.get("days", 30))
    except Exception:
        return jsonify({"status": "error", "message": "حجم یا تعداد روز نامعتبر است"}), 400

    if not name:
        return jsonify({"status": "error", "message": "نام کاربر الزامی است"}), 400

    if quota <= 0:
        return jsonify({"status": "error", "message": "حجم باید بیشتر از صفر باشد"}), 400

    if days <= 0:
        return jsonify({"status": "error", "message": "تعداد روز باید بیشتر از صفر باشد"}), 400

    user_uuid = str(uuid.uuid4())

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            """
            INSERT INTO users
            (name, uuid, quota_gb, expire_days, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, user_uuid, quota, days, datetime.now().isoformat())
        )

        conn.commit()
        conn.close()

        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ساخته شد"})

    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "این نام کاربری قبلاً وجود دارد"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/edit_user/<int:user_id>", methods=["POST"])
def edit_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    data = request.get_json(silent=True) or {}

    try:
        new_quota = float(data.get("quota_gb", 0))
        new_days = int(data.get("expire_days", 0))
    except Exception:
        return jsonify({"status": "error", "message": "مقادیر نامعتبر"}), 400

    if new_quota <= 0 or new_days <= 0:
        return jsonify({"status": "error", "message": "حجم و روز باید بیشتر از صفر باشند"}), 400

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute(
            "UPDATE users SET quota_gb=?, expire_days=? WHERE id=?",
            (new_quota, new_days, user_id)
        )

        conn.commit()
        conn.close()

        # بازسازی هسته چون امکان دارد کاربر ویرایش‌شده تمدید حجم شده باشد و باید دوباره فعال شود
        restart_xray()

        return jsonify({"status": "success", "message": "کاربر با موفقیت ویرایش شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/reset_user/<int:user_id>", methods=["POST"])
def reset_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    try:
        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT name FROM users WHERE id=?", (user_id,))
        row = c.fetchone()

        if row:
            xray_reset_user_stats(row["name"])

        c.execute(
            "UPDATE users SET used_bytes=0, created_at=? WHERE id=?",
            (datetime.now().isoformat(), user_id)
        )

        conn.commit()
        conn.close()

        # بازسازی فایل کانفیگ برای فعال شدن مجدد کاربر قطع شده در Xray
        restart_xray()

        return jsonify({"status": "success", "message": "ترافیک کاربر صفر شد"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("DELETE FROM users WHERE id=?", (user_id,))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "message": "کاربر با موفقیت حذف شد"})

@app.route("/api/toggle_user/<int:user_id>", methods=["POST"])
def toggle_user(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT enabled FROM users WHERE id=?", (user_id,))

    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    new_val = 0 if row[0] == 1 else 1

    c.execute("UPDATE users SET enabled=? WHERE id=?", (new_val, user_id))

    conn.commit()
    conn.close()

    restart_xray()

    return jsonify({"status": "success", "new_state": new_val})

@app.route("/api/user_config/<int:user_id>")
def user_config(user_id):
    if "admin" not in session:
        return jsonify({"status": "error"}), 401

    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()

    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "کاربر یافت نشد"}), 404

    host = request.host.split(":")[0]

    configs = make_all_configs(dict(user), host)

    sub_link = f"{request.host_url}sub/{user['uuid']}"

    return jsonify({
        "status": "success",
        "configs": configs,
        "sub": sub_link,
        "user": dict(user)
    })

@app.route("/sub/<user_uuid>")
def subscription(user_uuid):
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,))
    user = c.fetchone()

    conn.close()

    # اگر کاربر اصلاً در دیتابیس نبود ارور می‌دهد
    if not user:
        return ("User not found", 404)

    user_dict = dict(user)
    ua = request.headers.get("User-Agent", "").lower()

    client_keywords = [
        "v2ray", "clash", "sing-box", "hiddify",
        "nekobox", "streisand", "foxray", "shadowrocket", "v2box"
    ]

    is_client = any(k in ua for k in client_keywords)
    host = request.host.split(":")[0]

    # بررسی وضعیت واقعی ترافیک و اعتبار کاربر
    active, reason = is_user_active(user_dict)

    if active:
        all_configs = make_all_configs(user_dict, host)
    else:
        # اگر حجم کاربر تمام شده باشد، به جای کانفیگ های واقعی، کانفیگ اطلاع رسانی ارسال می شود
        all_configs = make_fake_config(reason, user_dict, host)

    # قالب متناسب با کلاینت های فیلترشکن (ارسال هدر مانیتورینگ حجم و سابسکریپشن)
    if is_client:
        raw_text = "\n".join(item["config"] for item in all_configs)
        encoded = base64.b64encode(raw_text.encode()).decode()
        
        resp = Response(encoded, mimetype="text/plain")
        resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
        return resp

    # قالب مشاهده در مرورگر (وب سایت سابسکریپشن)
    created_dt = datetime.fromisoformat(user_dict["created_at"])
    elapsed_days = (datetime.now() - created_dt).days
    days_left = max(0, user_dict["expire_days"] - elapsed_days)

    used_gb = round(user_dict["used_bytes"] / (1024 ** 3), 2)
    remaining_gb = max(0.0, round(user_dict["quota_gb"] - used_gb, 2))

    percent = (
        used_gb / user_dict["quota_gb"] * 100
        if user_dict["quota_gb"] > 0 else 0
    )

    raw_text = "\n".join(item["config"] for item in all_configs)
    encoded_sub = base64.b64encode(raw_text.encode()).decode()

    resp = Response(render_template(
        "subscription.html",
        user_name=user_dict["name"],
        used_gb=used_gb,
        quota_gb=user_dict["quota_gb"],
        remaining_gb=remaining_gb,
        days_left=days_left,
        percent=round(percent, 1),
        configs=all_configs,
        sub_raw=encoded_sub,
        sub_url=request.url
    ))
    resp.headers["Subscription-Userinfo"] = get_subscription_header(user_dict)
    return resp

def run_telegram_bot_thread():
    if not telebot:
        print("[Telegram Bot] telebot module not found. Skipping bot launch.")
        return

    while True:
        try:
            tg_token = get_setting("telegram_token", "").strip()
            tg_admin_id = get_setting("telegram_admin_id", "").strip()

            if not tg_token:
                time.sleep(10)
                continue

            bot = telebot.TeleBot(tg_token)

            @bot.message_handler(commands=['start'])
            def cmd_start(message):
                chat_id = str(message.chat.id)
                if chat_id == tg_admin_id:
                    markup = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
                    btn_status = telebot.types.KeyboardButton('📊 وضعیت پنل')
                    btn_users = telebot.types.KeyboardButton('👥 لیست کاربران')
                    markup.add(btn_status, btn_users)
                    
                    bot.send_message(
                        message.chat.id,
                        "⚡ **سلام ادمین گرامی!**\nبه پنل مدیریت تلگرامی Vega خوش آمدید.\nیکی از دکمه‌های زیر را انتخاب کنید:",
                        reply_markup=markup,
                        parse_mode="Markdown"
                    )
                else:
                    bot.send_message(
                        message.chat.id,
                        "👋 **سلام کاربر عزیز!**\nبرای استعلام مشخصات کانکشن خود، لطفاً **نام کاربری** یا **UUID** خود را ارسال کنید:"
                    )

            @bot.message_handler(func=lambda m: True)
            def handle_messages(message):
                text = message.text.strip()
                chat_id = str(message.chat.id)

                if chat_id == tg_admin_id:
                    if text == '📊 وضعیت پنل':
                        users = get_all_users()
                        total = len(users)
                        active = sum(1 for u in users if is_user_active(u)[0])
                        total_bytes = sum(u["used_bytes"] for u in users)
                        total_gb = round(total_bytes / (1024 ** 3), 2)

                        msg = (
                            f"🌐 **وضعیت سرور Vega**\n"
                            f"━━━━━━━━━━━━━━━━━━\n"
                            f"👥 کل کاربران: {total} کاربر\n"
                            f"🟢 کاربران فعال: {active} کاربر\n"
                            f"📊 مصرف کل دیتابیس: {total_gb} GB\n"
                            f"━━━━━━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                    elif text == '👥 لیست کاربران':
                        users = get_all_users()
                        if not users:
                            bot.send_message(chat_id, "هیچ کاربری یافت نشد.")
                            return

                        msg = "👥 **لیست کاربران پنل (نمایش ۱۵ کاربر آخر):**\n\n"
                        for u in users[:15]:
                            active, _ = is_user_active(u)
                            status = "🟢" if active else "🔴"
                            used = round(u["used_bytes"] / (1024 ** 3), 2)
                            msg += f"{status} `{u['name']}` | {used}/{u['quota_gb']} GB\n"

                        if len(users) > 15:
                            msg += f"\nو {len(users) - 15} کاربر دیگر..."

                        bot.send_message(chat_id, msg, parse_mode="Markdown")

                else:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT * FROM users WHERE name = ? OR uuid = ?", (text, text))
                    user = c.fetchone()
                    conn.close()

                    if user:
                        u = dict(user)
                        used_gb = round(u["used_bytes"] / (1024 ** 3), 2)
                        
                        active, reason = is_user_active(u)
                        if active:
                            status = "فعال 🟢"
                        else:
                            if reason == "limit_exceeded":
                                status = "اتمام حجم 🔴"
                            elif reason == "expired":
                                status = "پایان اعتبار زمانی 🔴"
                            else:
                                status = "غیرفعال 🔴"
                        
                        try:
                            created_dt = datetime.fromisoformat(u["created_at"])
                            elapsed_days = (datetime.now() - created_dt).days
                            days_left = max(0, u["expire_days"] - elapsed_days)
                        except Exception:
                            days_left = u["expire_days"]

                        msg = (
                            f"👤 **مشخصات اشتراک شما**\n"
                            f"━━━━━━━━━━━━━\n"
                            f"🆔 نام کاربری: `{u['name']}`\n"
                            f"⚡ وضعیت اکانت: {status}\n"
                            f"📊 ترافیک مصرفی: {used_gb} GB\n"
                            f"💾 سقف حجم کل: {u['quota_gb']} GB\n"
                            f"📅 اعتبار باقی‌مانده: {days_left} روز\n"
                            f"━━━━━━━━━━━━━"
                        )
                        bot.send_message(chat_id, msg, parse_mode="Markdown")
                    else:
                        bot.send_message(chat_id, "❌ کاربری با این نام یا UUID یافت نشد.")

            print("[Telegram Bot] Bot polling started successfully.")
            bot.infinity_polling(timeout=10, long_polling_timeout=5)

        except Exception as e:
            print("[Telegram Bot] Polling crash/error, restarting in 10s:", e)
            time.sleep(10)

def start_telegram_bot():
    t = threading.Thread(target=run_telegram_bot_thread, daemon=True)
    t.start()

if __name__ == "__main__":
    init_db()
    restart_xray()
    start_nginx()
    start_stats_collector()
    start_telegram_bot()
    app.run(host="127.0.0.1", port=FLASK_PORT)
