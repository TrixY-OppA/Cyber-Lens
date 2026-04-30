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

df = pd.read_csv("data/cybersecurity_attacks.csv")
df = df.head(500)  # import first 500 rows

for _, row in df.iterrows():
    try:
        # Insert attacker
        cursor.execute("""
            INSERT INTO attacker (source_ip, source_port, country)
            VALUES (%s, %s, %s)
        """, (str(row.get('Source IP Address', '0.0.0.0')),
              int(row.get('Source Port', 0)),
              str(row.get('Country', 'Unknown'))))
        attacker_id = cursor.lastrowid

        # Insert system
        cursor.execute("""
            INSERT INTO affected_system (ip_address, protocol)
            VALUES (%s, %s)
        """, (str(row.get('Destination IP Address', '0.0.0.0')),
              str(row.get('Protocol', 'TCP'))))
        system_id = cursor.lastrowid

        # Insert incident
        cursor.execute("""
            INSERT INTO incident 
            (threat_id, attacker_id, system_id, analyst_id, 
             timestamp, action_taken, status, anomaly_score)
            VALUES (%s, %s, %s, %s, NOW(), %s, %s, %s)
        """, (1, attacker_id, system_id, 1,
              str(row.get('Action Taken', 'Blocked')),
              'Pending',
              float(row.get('Anomaly Scores', 0))))

        conn.commit()
    except Exception as e:
        print(f"Skipped row: {e}")
        conn.rollback()

print("Done! Data imported.")
cursor.close()
conn.close()