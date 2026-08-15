import json
users = json.load(open("data/users.json"))
phone = "+919876543210"
phone_clean = phone.replace(" ", "").replace("-", "")
print("Input phone_clean:", repr(phone_clean))
for k, v in users.items():
    stored = (v.get("phone", "") or "").replace(" ", "").replace("-", "")
    if stored:
        print(f"Key: {k}, Stored: {repr(stored)}, Match: {stored == phone_clean}")
        if not stored.startswith("+91") and phone_clean.startswith("+91"):
            print(f"  Strip +91: {stored == phone_clean[3:]}")
        if stored.startswith("+91") and not phone_clean.startswith("+91") and len(phone_clean) == 10:
            print(f"  Add +91: {stored[3:] == phone_clean}")
