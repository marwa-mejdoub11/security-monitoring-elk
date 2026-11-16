import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from faker import Faker

fake = Faker()
USERS = ["admin", "m.laurent", "j.dupont", "s.petit", "root", "t.renard"]
COUNTRIES = ["Tunisia", "France", "Germany", "Russia", "United States", "Singapore"]

def make_event(ts, ip, username, status, country, attack_type=None):
    return {
        "@timestamp": ts.isoformat(),
        "event_id": f"EVT-{uuid.uuid4().hex[:8]}",
        "event_type": "authentication",
        "username": username,
        "source_ip": ip,
        "status": status,
        "severity": "high" if status == "failed" else "low",
        "country": country,
        "message": "Échec de connexion" if status == "failed" else "Connexion réussie",
        "attack_type": attack_type or "none",
    }

def generate(n=500, output="data/uploads/auth_logs.json"):
    now = datetime.now(timezone.utc)
    events = []

    # Trafic normal
    for _ in range(n):
        ts = now - timedelta(minutes=random.randint(0, 60 * 24))
        status = random.choices(["success", "failed"], weights=[75, 25])[0]
        events.append(make_event(ts, fake.ipv4_public(), random.choice(USERS),
                                 status, random.choice(COUNTRIES)))

    # Attaques par force brute : 6 échecs en moins de 5 minutes depuis une même IP
    for _ in range(5):
        ip = fake.ipv4_public()
        country = random.choice(COUNTRIES)
        start = now - timedelta(minutes=random.randint(10, 600))
        for i in range(6):
            events.append(make_event(start + timedelta(seconds=i * 30), ip,
                                     "admin", "failed", country, "brute_force"))

    events.sort(key=lambda e: e["@timestamp"])
    with open(output, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"{len(events)} logs générés dans {output}")

if __name__ == "__main__":
    generate()