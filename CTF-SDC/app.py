# app.py
# CTF challenge: require X-Forwarded-For IP to match allowed list AND
# User-Agent to be exactly "SDC". Hints in HTML comments (view-source).
# Flag: CTF{RIYADH_SPOOF_21}

from flask import Flask, render_template_string, request
from datetime import datetime, timezone
import ipaddress

app = Flask(__name__)

# configuration
CONFIG = {
    "flag": "CTF{RIYADH_SPOOF_21}",
    "riyadh_cidr_list": ["212.107.116.238/32"],  # allowed IP (single IP)
    "required_user_agent": "SDC"                  # exact match required
}

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>WE WILL MEET IN RIYADH</title>
<style>
:root{--primary:#2A7F7F;--accent:#66FF66;--bg1:#071e1e;--bg2:#083737;--text:#f7fbfb}
html,body{height:100%;margin:0;font-family:Inter,system-ui,Arial;background:linear-gradient(135deg,var(--bg1),var(--bg2));color:var(--text)}
.wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:32px;box-sizing:border-box}
.card{width:100%;max-width:880px;text-align:center;padding:36px;border-radius:14px;background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(0,0,0,0.06));border:1px solid rgba(255,255,255,0.03)}
.bar{width:96px;height:8px;border-radius:999px;margin:0 auto 14px auto;background:linear-gradient(90deg,var(--primary),rgba(42,127,127,0.85))}
h1{margin:6px 0 8px 0;font-size:32px;color:var(--primary);letter-spacing:1px}
.flag{margin-top:14px;display:inline-block;padding:12px 16px;border-radius:8px;background:#071e1e;color:var(--accent);font-family:monospace;font-weight:700}
.note{margin-top:12px;color:rgba(255,255,255,0.78);font-size:14px}
code{background:rgba(0,0,0,0.3);padding:4px 8px;border-radius:6px;font-family:monospace;direction:ltr}
small.debug{display:block;margin-top:12px;color:rgba(255,255,255,0.45);font-size:12px}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card" role="main">
      <div class="bar" aria-hidden="true"></div>
      <h1>WE WILL MEET IN RIYADH</h1>

      {% if show_flag %}
        <div class="flag">{{ flag }}</div>
        <div class="note">Flag revealed — exact User-Agent and X-Forwarded-For matched.</div>
      {% else %}
        <!-- Hint: set X-Forwarded-For to a Riyadh IP (e.g. 212.***.***.***) and set User-Agent to "SDC" -->
      {% endif %}

    </div>
  </div>
</body>
</html>
"""

# helpers
def parse_x_forwarded_for(req):
    """Return first IP in X-Forwarded-For header (if any), else None."""
    xff = req.headers.get('X-Forwarded-For')
    if not xff:
        return None
    parts = [p.strip() for p in xff.split(',') if p.strip()]
    return parts[0] if parts else None

def ip_in_allowed_list(ip_str):
    """Check whether ip_str belongs to any CIDR in CONFIG['riyadh_cidr_list']."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for cidr in CONFIG['riyadh_cidr_list']:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if ip in net:
                return True
        except Exception:
            continue
    return False

@app.route('/')
def index():
    # read first IP from X-Forwarded-For (if present)
    xff_ip = parse_x_forwarded_for(request)

    # read user-agent header exactly
    ua = request.headers.get('User-Agent', '')

    # exact checks
    ip_ok = xff_ip is not None and ip_in_allowed_list(xff_ip)
    ua_ok = (ua.strip() == CONFIG['required_user_agent'])

    show_flag = ip_ok and ua_ok

    # debug info
    remote_addr = request.remote_addr or 'unknown'
    server_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return render_template_string(
        HTML,
        show_flag=show_flag,
        flag=CONFIG['flag'],
        remote_addr=remote_addr,
        server_utc=server_utc
    )

if __name__ == '__main__':
    print("Starting CTF app on http://127.0.0.1:5000")

    app.run(host='0.0.0.0', port=5000, debug=False)
