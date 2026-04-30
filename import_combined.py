import pandas as pd
import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    port=3308,
    user="root",
    password="Tejass@06",
    database="cyberlens"
)
cursor = conn.cursor()

df = pd.read_csv("data/malware_combined.csv")
df = df.head(500)

# Map attack types to threat IDs
attack_map = {
    'DDoS': 1, 'Phishing': 2, 'Malware': 3, 'Ransomware': 4,
    'SQL Injection': 5, 'Intrusion': 6, 'Brute Force': 7,
    'Man-in-Middle': 8, 'Zero-Day Exploit': 9, 'Spyware': 10
}

imported = 0
for _, row in df.iterrows():
    try:
        attack_type = str(row.get('Attack Type', 'Malware'))
        threat_id = attack_map.get(attack_type, 3)

        cursor.execute("""
            INSERT INTO attacker (source_ip, source_port, country)
            VALUES (%s, %s, %s)
        """, (str(row.get('Source IP Address', '0.0.0.0')),
              int(float(str(row.get('Source Port', 0)).replace('nan','0') or 0)),
              str(row.get('Geo-location Data', 'Unknown'))))
        attacker_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO affected_system (ip_address, protocol)
            VALUES (%s, %s)
        """, (str(row.get('Destination IP Address', '0.0.0.0')),
              str(row.get('Protocol', 'TCP'))))
        system_id = cursor.lastrowid

        analyst_id = (imported % 4) + 1

        cursor.execute("""
            INSERT INTO incident
            (threat_id, attacker_id, system_id, analyst_id,
             timestamp, action_taken, status, anomaly_score)
            VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
        """, (threat_id, attacker_id, system_id, analyst_id,
              str(row.get('Action Taken', 'Blocked')),
              'Pending',
              float(str(row.get('Anomaly Scores', 0)).replace('nan','0') or 0)))

        conn.commit()
        imported += 1
    except Exception as e:
        conn.rollback()

print(f"Done! Imported {imported} records from malware_combined.csv")
cursor.close()
conn.close()