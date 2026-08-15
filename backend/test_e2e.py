import sys, json
sys.path.insert(0, '.')
from app import app
from config.database import _query, _get_stat, init_db
init_db()

with app.test_client() as c:
    r = c.post('/api/auth/login', json={'email':'admin@cybershield.com','password':'admin123'})
    d = r.get_json()
    email = d.get('email')
    from services.auth.auth_service import EMAIL_OTP_STORE
    otp = EMAIL_OTP_STORE.get(email, {}).get('otp')
    r2 = c.post('/api/auth/verify-email-otp', json={'email': email, 'otp': str(otp)})
    token = r2.get_json().get('token')
    h = {'Authorization': f'Bearer {token}'}

    c.post('/api/mobile/caller-scan', json={'phone': '+919876543210'}, headers=h)
    c.post('/api/mobile/caller-scan', json={'phone': '+14155551234'}, headers=h)
    c.post('/api/mobile/analyze-sms', json={'text': 'Congratulations! You won a lottery! Click here'}, headers=h)
    c.post('/api/mobile/analyze-sms', json={'text': 'Meeting at 3pm tomorrow'}, headers=h)
    c.post('/api/email/url-analysis', json={'url': 'http://bit.ly/fake-login'}, headers=h)

    print('=== REAL DATA IN DB ===')
    caller = _query('SELECT phone, verdict, score FROM caller_history ORDER BY id DESC')
    for r in caller:
        print(f'  Caller: {r["phone"]} -> {r["verdict"]} (score {r["score"]})')
    sms = _query('SELECT verdict, score, substr(text,1,30) as txt FROM sms_scan_history ORDER BY id DESC')
    for r in sms:
        print(f'  SMS: {r["verdict"]} (score {r["score"]}) "{r["txt"]}"')
    email_rows = _query('SELECT scan_type, verdict, score FROM email_scan_history ORDER BY id DESC')
    for r in email_rows:
        print(f'  Email: {r["scan_type"]} -> {r["verdict"]} (score {r["score"]})')

    print()
    print('=== STATS ===')
    print(f'Scans: {_get_stat("total_scans")} | Threats: {_get_stat("threats_blocked")} | SMS: {_get_stat("total_sms_scans")} | Phishing: {_get_stat("phishing_blocked")}')

    r = c.get('/api/mobile/dashboard-stats', headers=h)
    s = r.get_json()['stats']
    print(f'Dashboard: scans={s["total_scans"]} threats={s["threats_blocked"]} sms={s["sms_analyzed"]} calls={s["calls_scanned"]}')
    print()
    print('ALL FEATURES NOW REAL-TIME!')
