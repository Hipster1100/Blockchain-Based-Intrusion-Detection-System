import sqlite3
import json

# Connect to your blockchain.db
conn = sqlite3.connect('blockchain.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

print("="*70)
print("🧱 Last 5 Blocks in Blockchain (from SQLite)")
print("="*70)

cursor.execute("""
    SELECT block_index, timestamp, hash, previous_hash, data 
    FROM blocks 
    ORDER BY block_index DESC 
    LIMIT 5
""")

rows = cursor.fetchall()
for r in rows:
    print(f"\nBlock #{r['block_index']}")
    print(f"Timestamp: {r['timestamp']}")
    print(f"Hash: {r['hash']}")
    print(f"Prev: {r['previous_hash']}")
    print("Data:")
    try:
        data = json.loads(r['data'])
        for k, v in data.items():
            print(f"  {k}: {v}")
    except:
        print("  Raw:", r['data'])
    print("-"*70)

conn.close()
