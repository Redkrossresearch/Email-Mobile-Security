import sys
sys.path.insert(0, '.')
from config.database import _insert, _query, init_db
init_db()

try:
    _insert('caller_history', {
        'phone': '+919876543210', 'e164': '+919876543210',
        'country_iso': 'IN', 'country_name': 'India',
        'carrier': 'Airtel', 'number_type': 'mobile',
        'score': 25, 'risk_level': 'low', 'verdict': 'VERIFIED',
        'tags': '["safe"]', 'explanation': 'Test', 'recommendation': 'Safe',
        'scanned_by': 'test'
    })
    print('Insert OK')
    rows = _query('SELECT * FROM caller_history')
    print('Rows:', len(rows))
    if rows:
        print(dict(rows[0]))
except Exception as e:
    print('ERROR:', e)
    import traceback; traceback.print_exc()
