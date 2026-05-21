from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import os
import json
import sqlite3
import requests
import secrets
import re
from datetime import datetime, timedelta
from collections import Counter
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.jinja_env.globals['datetime'] = datetime
app.secret_key = "1312"

# ── Config ──────────────────────────────────────────────────────────

RESEND_API_KEY = "re_CS4mZtm7_AAwJqbzkgYfN15n1i5fkQ2bK"
ADMIN_EMAIL    = "codnellsmall@gmail.com"
FROM_EMAIL     = "KingSTrips <onboarding@resend.dev>"

DATA_DIR     = os.path.join(os.path.dirname(__file__), "data")
DB_FILE      = os.path.join(DATA_DIR, "submissions.db")
ADMINS_FILE  = os.path.join(DATA_DIR, "admins.json")
CODES_FILE   = os.path.join(DATA_DIR, "codes.json")
ADMIN_PASSWORD = "admin1312"
LEGACY_HASH  = generate_password_hash(ADMIN_PASSWORD)


# ── Database helpers ─────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            subject TEXT NOT NULL,
            destination TEXT,
            travel_date TEXT,
            travellers TEXT,
            budget TEXT,
            message TEXT,
            status TEXT DEFAULT 'new',
            ts TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def load_submissions():
    init_db()
    conn = get_db()
    rows = conn.execute('SELECT * FROM submissions ORDER BY ts DESC').fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_submission(record):
    init_db()
    conn = get_db()
    conn.execute('''
        INSERT OR REPLACE INTO submissions
            (id, name, email, phone, subject, destination,
             travel_date, travellers, budget, message, status, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        record.get("id"), record.get("name"), record.get("email"),
        record.get("phone"), record.get("subject"), record.get("destination"),
        record.get("travel_date"), record.get("travellers"), record.get("budget"),
        record.get("message"), record.get("status", "new"), record.get("ts")
    ))
    conn.commit()
    conn.close()


# ── 2FA helpers ──────────────────────────────────────────────────────

def load_codes():
    try:
        with open(CODES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_codes(codes):
    with open(CODES_FILE, "w", encoding="utf-8") as f:
        json.dump(codes, f, indent=2, ensure_ascii=False)


def load_admins():
    try:
        with open(ADMINS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_admins(admins):
    with open(ADMINS_FILE, "w", encoding="utf-8") as f:
        json.dump(admins, f, indent=2, ensure_ascii=False)


def find_admin(username):
    for a in load_admins():
        if a.get("username", "").lower() == username.lower():
            return a
    return None


def is_admin():
    return session.get("admin_logged_in") is True


def verify_admin_password(raw_password):
    admins = load_admins()
    if admins:
        user  = session.get("admin_user")
        entry = find_admin(user) if user else None
        if entry and check_password_hash(entry["password_hash"], raw_password):
            return True
    return check_password_hash(LEGACY_HASH, raw_password)


def _code_record(username, raw_code, email):
    now    = datetime.utcnow()
    return {
        "username":   username,
        "code":       raw_code,
        "email":      email,
        "created_at": now.isoformat(timespec="milliseconds"),
        "expires_at": (now + timedelta(minutes=10)).isoformat(timespec="milliseconds"),
        "used":       False,
    }


def _get_2fa_pending(username):
    for c in reversed(load_codes()):
        if c.get("username") == username and not c.get("used"):
            return c
    return None


def _cleanup_used_codes(username=None):
    codes = load_codes()
    if username:
        codes = [c for c in codes
                 if not (c.get("username") == username and c.get("used"))]
    else:
        codes = [c for c in codes if not c.get("used")]
    save_codes(codes)


def generate_and_send_2fa(username, email):
    code   = str(secrets.randbelow(900_000) + 100_000)
    record = _code_record(username, code, email)
    codes  = load_codes()
    codes.append(record)
    save_codes(codes)

    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;">
      <div style="max-width:520px;margin:auto;background:white;padding:40px;border-radius:16px;text-align:center;">
        <h1 style="color:#0d6efd;">KingSTrips</h1>
        <h2 style="margin-bottom:.5rem;">Your Admin Login Code</h2>
        <p style="color:#64748b;font-size:.95rem;">Enter this 6-digit code to finish signing in.</p>
        <div style="background:#f1f5f9;border-radius:14px;padding:24px;margin:1.5rem 0;">
          <span style="font-size:3rem;font-weight:800;letter-spacing:.4rem;color:#0f172a;">{code}</span>
        </div>
        <p style="font-size:.82rem;color:#94a3b8;">
          This code expires in <strong>10 minutes</strong>.<br>
          If you didn't request this, you can safely ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #f1f5f9;margin:1.5rem 0;">
        <p style="font-size:.75rem;color:#cbd5e1;">2026 KingSTrips (Pty) Ltd</p>
      </div>
    </body>
    </html>
    """
    text = f"KingSTrips Admin Login Code\n\n{code}\n\nThis code expires in 10 minutes."
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type":  "application/json",
        },
        json={"from": FROM_EMAIL, "to": [email],
              "subject": "Your KingSTrips Admin Login Code",
              "html": html, "text": text},
        timeout=10,
    )
    return resp.status_code, resp.json()



# ═══ ADMIN AUTH ROUTES ══════════════════════════════════════════════

@app.route("/admin/2fa/send", methods=["POST"])
def admin_2fa_send():
    data     = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "Username required."}), 400

    entry = find_admin(username)
    if not entry:
        return jsonify({"error": "Account not found."}), 404

    email = entry.get("email", "")
    if not email:
        return jsonify({"error": "No email on file for this account."}), 400

    _cleanup_used_codes(username)
    st, body = generate_and_send_2fa(username, email)
    if st in (200, 201, 202):
        return jsonify({"status": "sent", "masked": email[:3] + "***" + email[-2:]})
    return jsonify({"error": "Failed to send code.", "detail": body}), 500


@app.route("/admin/2fa/verify", methods=["POST"])
def admin_2fa_verify():
    data     = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    code     = (data.get("code") or "").strip()

    record = _get_2fa_pending(username)
    if not record:
        return jsonify({"error": "No active code. Request a new one."}), 400

    try:
        exp = datetime.fromisoformat(record["expires_at"])
    except Exception:
        exp = None
    if exp and datetime.utcnow() > exp:
        return jsonify({"error": "Code expired. Request a new one."}), 400
    if code != record["code"]:
        return jsonify({"error": "Incorrect code."}), 400

    codes = load_codes()
    u     = record["username"]
    exp_r = record["expires_at"]
    for rec in codes:
        if (rec.get("username") == u
                and rec.get("expires_at") == exp_r
                and not rec["used"]):
            rec["used"] = True
            break
    save_codes(codes)

    session["admin_logged_in"] = True
    session["admin_user"]       = username
    return jsonify({
        "status":   "authenticated",
        "redirect": url_for("admin_dashboard"),
    })


@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email",    "").strip()
        password = request.form.get("password", "").strip()
        confirm  = request.form.get("confirm",  "").strip()

        if not username or not email or not password:
            return render_template("admin_register.html",
                                   error="Please fill in all required fields.")
        if len(username) < 3:
            return render_template("admin_register.html",
                                   error="Username must be at least 3 characters.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return render_template("admin_register.html",
                                   error="Please enter a valid email address.")
        if len(password) < 5:
            return render_template("admin_register.html",
                                   error="Password must be at least 5 characters.")
        if password != confirm:
            return render_template("admin_register.html",
                                   error="Passwords do not match.")

        admins = load_admins()
        for a in admins:
            if a.get("username", "").lower() == username.lower():
                return render_template("admin_register.html",
                                       error="That username is already taken.")
            if a.get("email", "").lower() == email.lower():
                return render_template("admin_register.html",
                                       error="That email address is already registered.")

        admins.append({
            "username":      username,
            "email":         email,
            "password_hash": generate_password_hash(password),
            "created":       datetime.utcnow().isoformat(timespec="milliseconds"),
        })
        save_admins(admins)
        return render_template("admin_register.html",
                               success="Account created! You can now log in.",
                               error=None)

    return render_template("admin_register.html", error=None)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    # ── POST: AJAX (JSON) ─────────────────────────────────────────
    if request.method == "POST" and request.is_json:
        data = request.get_json(force=True) or {}

        # Step 3 — verify 2FA code
        if "code" in data:
            username = (data.get("username") or "").strip()
            code     = (data.get("code") or "").strip()
            record   = _get_2fa_pending(username)
            if not record:
                return jsonify({"error": "No active code. Request a new one."}), 400
            try:
                exp = datetime.fromisoformat(record["expires_at"])
            except Exception:
                exp = None
            if exp and datetime.utcnow() > exp:
                return jsonify({"error": "Code expired. Request a new one."}), 400
            if code != record["code"]:
                return jsonify({"error": "Incorrect code."}), 400

            codes = load_codes()
            u     = record["username"]
            exp_r = record["expires_at"]
            for rec in codes:
                if (rec.get("username") == u
                        and rec.get("expires_at") == exp_r
                        and not rec["used"]):
                    rec["used"] = True
                    break
            save_codes(codes)

            session["admin_logged_in"] = True
            session["admin_user"]       = username
            return jsonify({
                "status":   "authenticated",
                "redirect": url_for("admin_dashboard"),
            })

        # Step 2 — check credentials
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        admins   = load_admins()
        entry    = find_admin(username)

        if entry and check_password_hash(entry["password_hash"], password):
            email = entry.get("email", "")
            if not email:
                return jsonify({"error": "No email on file for this account."}), 400
            _cleanup_used_codes(username)
            st, body = generate_and_send_2fa(username, email)
            if st not in (200, 201, 202):
                return jsonify({"error": "Could not send verification code. Try again."}), 500
            return jsonify({
                "status":       "2fa_required",
                "masked_email": email[:3] + "***" + email[-2:],
                "username":     username,
            })

        # Legacy fallback
        if admins == [] and check_password_hash(LEGACY_HASH, password):
            session["admin_logged_in"] = True
            session["admin_user"]       = ""
            return jsonify({
                "status":   "authenticated",
                "redirect": url_for("admin_dashboard"),
            })

        return jsonify({"error": "Invalid username or password."}), 401

    # ── POST: form (non-JS fallback) ─────────────────────────────
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admins   = load_admins()

        entry = find_admin(username)
        if entry and check_password_hash(entry["password_hash"], password):
            email = entry.get("email", "")
            if email:
                _cleanup_used_codes(username)
                st, _ = generate_and_send_2fa(username, email)
                if st in (200, 201, 202):
                    return redirect(url_for("admin_2fa_page", u=username))
                return render_template("admin_login.html",
                                       error="Could not send verification email.",
                                       step2=False)
            return render_template("admin_login.html",
                                   error="No email on file. Contact an existing admin.",
                                   step2=False)

        if admins == [] and check_password_hash(LEGACY_HASH, password):
            session["admin_logged_in"] = True
            session["admin_user"]       = ""
            return redirect(url_for("admin_dashboard"))

        return render_template("admin_login.html",
                               error="Invalid username or password.",
                               step2=False)

    # ── GET ──
    return render_template("admin_login.html", error=None, step2=False)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_user",       None)
    return redirect(url_for("index"))


@app.route("/admin/2fa")
def admin_2fa_page():
    username = request.args.get("u", "").strip()
    if not username:
        return redirect(url_for("admin_login"))
    entry = find_admin(username)
    if not entry:
        return redirect(url_for("admin_login"))
    email  = entry.get("email", "")
    if not email:
        return redirect(url_for("admin_login"))
    masked = email[:3] + "***" + email[-2:]
    return render_template("admin_2fa.html",
                           username=username,
                           masked_email=masked)


@app.route("/admin/dashboard")
def admin_dashboard():
    if not is_admin():
        return redirect(url_for("admin_login"))

    subs        = load_submissions()
    recent      = subs[:10]
    unanswered  = sum(1 for s in subs if s.get("status") == "new")
    viewed      = len(subs) - unanswered

    # ── Chart 1: Enquiries by date (last 14 days) ────────────────
    today       = datetime.utcnow().date()
    date_labels = [(today - timedelta(days=i)).strftime("%b %d")
                   for i in reversed(range(14))]
    date_counts = {
        (today - timedelta(days=i)).strftime("%b %d"): 0
        for i in range(14)
    }
    for s in subs:
        try:
            key = datetime.strptime(s["ts"][:10], "%Y-%m-%d").date().strftime("%b %d")
            if key in date_counts:
                date_counts[key] += 1
        except Exception:
            pass
    chart_dates_labels = json.dumps(date_labels)
    chart_dates_data   = json.dumps([date_counts.get(d, 0) for d in date_labels])

    # ── Chart 2: Top destinations ─────────────────────────────────
    dest_counter = Counter(
        s.get("destination", "").strip() or "Not specified" for s in subs
    )
    top_dests         = dest_counter.most_common(6)
    chart_dest_labels = json.dumps([d for d, _ in top_dests])
    chart_dest_data   = json.dumps([c for _, c in top_dests])

    # ── Chart 3: Trip type breakdown ─────────────────────────────
    trip_counter = Counter(
        s.get("subject", "").strip() or "Not specified" for s in subs
    )
    top_trips         = trip_counter.most_common(6)
    chart_trip_labels = json.dumps([t for t, _ in top_trips])
    chart_trip_data   = json.dumps([c for _, c in top_trips])

    # ── Chart 4: Monthly totals (last 6 months) ──────────────────
    today_dt    = datetime.utcnow()
    month_labels = []
    month_data   = []
    for i in range(5, -1, -1):
        m     = (today_dt.replace(day=1) - timedelta(days=i * 30))
        mkey  = m.strftime("%b %Y")
        count = sum(
            1 for s in subs
            if s.get("ts", "")[:7] == m.strftime("%Y-%m")
        )
        month_labels.append(mkey)
        month_data.append(count)
    chart_month_labels = json.dumps(month_labels)
    chart_month_data   = json.dumps(month_data)

    # ── Derived stats ────────────────────────────────────────────
    all_destinations  = len(dest_counter)
    all_trip_types    = len(trip_counter)
    response_rate     = round((viewed / len(subs) * 100), 1) if subs else 0
    most_popular_dest = top_dests[0][0]  if top_dests else ""
    most_popular_trip = top_trips[0][0]  if top_trips else ""

    most_active_day   = ""
    most_active_count = 0
    for d_label, cnt in date_counts.items():
        if cnt > most_active_count:
            most_active_count = cnt
            most_active_day   = d_label

    avg_group_size = "\u2014"
    try:
        sizes = [
            int(s["travellers"])
            for s in subs
            if s.get("travellers", "").strip().isdigit()
        ]
        avg_group_size = round(sum(sizes) / len(sizes), 1) if sizes else "\u2014"
    except Exception:
        pass

    return render_template(
        "admin.html",
        total_enquiries   = len(subs),
        unanswered        = unanswered,
        viewed            = viewed,
        recent            = recent,
        all_submissions   = subs,
        ADMIN_EMAIL       = ADMIN_EMAIL,
        chart_dates_labels = chart_dates_labels,
        chart_dates_data   = chart_dates_data,
        chart_dest_labels  = chart_dest_labels,
        chart_dest_data    = chart_dest_data,
        chart_trip_labels  = chart_trip_labels,
        chart_trip_data    = chart_trip_data,
        chart_month_labels = chart_month_labels,
        chart_month_data   = chart_month_data,
        all_destinations   = all_destinations,
        all_trip_types     = all_trip_types,
        response_rate      = response_rate,
        most_active_day    = most_active_day,
        most_active_count  = most_active_count,
        most_popular_dest  = most_popular_dest,
        most_popular_trip  = most_popular_trip,
        avg_group_size     = avg_group_size,
    )


# ═══════════════════════════════════════════════════════════════════
#  PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html", active_page="home")


@app.route("/about")
def about():
    return render_template("about.html", active_page="about")


@app.route("/trips")
def trips():
    return render_template("Trips.html", active_page="trips")


@app.route("/services")
def services():
    return render_template("services.html", active_page="services")


@app.route("/contact")
def contact():
    return render_template("contact.html", active_page="contact")


@app.route("/contact", methods=["POST"])
def contact_submit():
    data    = request.get_json(force=True, silent=True) or request.form
    name    = data.get("user_name")  or data.get("name",   "")
    email   = data.get("user_email") or data.get("email",  "")
    phone   = data.get("phone",      "")
    subject = data.get("subject",    "")
    dest    = data.get("destination", "")
    tdate   = data.get("travel_date", "")
    pax     = data.get("travellers",  "")
    budget  = data.get("budget",     "")
    notes   = data.get("message",    "")

    if not name or not email or not subject:
        return jsonify({
            "status":  "error",
            "message": "Name, email, and subject are required.",
        }), 400

    customer_html = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;">
      <div style="max-width:600px;margin:auto;background:white;padding:40px;border-radius:16px;">
        <h1 style="color:#0d6efd;">KingSTrips</h1>
        <h2>Travel Enquiry Received</h2>
        <p>Hello {name},</p>
        <p>Thank you for contacting KingSTrips.
           We received your travel enquiry and will get back to you shortly.</p>
        <hr>
        <p><strong>Full Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Phone:</strong> {phone}</p>
        <p><strong>Trip Type:</strong> {subject}</p>
        <p><strong>Destination:</strong> {dest}</p>
        <p><strong>Travel Date:</strong> {tdate}</p>
        <p><strong>Number of Travellers:</strong> {pax}</p>
        <p><strong>Budget Range:</strong> {budget}</p>
        <hr>
        <p><strong>Additional Message:</strong></p>
        <p>{notes}</p>
        <hr>
        <p style="font-size:14px;color:#777;">2026 KingSTrips</p>
      </div>
    </body>
    </html>
    """

    admin_html = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:40px;">
      <div style="max-width:600px;margin:auto;background:white;padding:40px;border-radius:16px;">
        <h1 style="color:#0d6efd;">New Travel Enquiry</h1>
        <p><strong>Full Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Phone:</strong> {phone}</p>
        <p><strong>Trip Type:</strong> {subject}</p>
        <p><strong>Destination:</strong> {dest}</p>
        <p><strong>Travel Date:</strong> {tdate}</p>
        <p><strong>Number of Travellers:</strong> {pax}</p>
        <p><strong>Budget Range:</strong> {budget}</p>
        <hr>
        <p><strong>Additional Message:</strong></p>
        <p>{notes}</p>
        <hr>
        <p style="font-size:14px;color:#777;">Sent from KingSTrips Website</p>
      </div>
    </body>
    </html>
    """

    try:
        headers = {
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type":  "application/json",
        }

        customer_response = requests.post(
            "https://api.resend.com/emails",
            headers=headers,
            json={
                "from":    FROM_EMAIL,
                "to":      [ADMIN_EMAIL],
                "reply_to": email,
                "subject": f"Customer Copy - {subject}",
                "html":    customer_html,
            },
            timeout=10,
        )

        admin_response = requests.post(
            "https://api.resend.com/emails",
            headers=headers,
            json={
                "from":    FROM_EMAIL,
                "to":      [ADMIN_EMAIL],
                "reply_to": email,
                "subject": f"New Contact Form Submission - {subject}",
                "html":    admin_html,
            },
            timeout=10,
        )

        print("Customer Email:", customer_response.status_code, customer_response.text)
        print("Admin Email:",    admin_response.status_code,    admin_response.text)

        if (customer_response.status_code in [200, 201]
                and admin_response.status_code in [200, 201]):
            save_submission({
                "id":          datetime.utcnow().isoformat(timespec="milliseconds"),
                "name":        name,
                "email":       email,
                "phone":       phone,
                "subject":     subject,
                "destination": dest,
                "travel_date": tdate,
                "travellers":  pax,
                "budget":      budget,
                "message":     notes,
                "status":      "new",
                "ts":          datetime.utcnow().isoformat(timespec="milliseconds"),
            })
            return jsonify({
                "status":  "success",
                "message": "Message sent successfully.",
            }), 200

        return jsonify({
            "status":  "error",
            "message": "Email delivery partially failed.",
        }), 500

    except Exception as e:
        print("EMAIL ERROR:", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/images")
def get_images():
    images_folder = os.path.join(app.static_folder, "images")
    if not os.path.exists(images_folder):
        return jsonify([])

    media_files = []
    for filename in sorted(os.listdir(images_folder)):
        filepath = os.path.join(images_folder, filename)
        if not os.path.isfile(filepath):
            continue
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        if ext in ("jpg", "jpeg", "png", "gif", "webp"):
            media_files.append({"name": filename, "type": "image",
                                "url": f"/static/images/{filename}"})
        elif ext in ("mp4", "webm", "mov"):
            media_files.append({"name": filename, "type": "video",
                                "url": f"/static/images/{filename}"})

    return jsonify(media_files)


if __name__ == "__main__":
    app.run(debug=True)
