import sqlite3, os
def init_db(path):
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS domains(domain TEXT PRIMARY KEY)")
    c.execute("""CREATE TABLE IF NOT EXISTS results(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        expires TEXT,
        days_left INTEGER,
        checked_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()

def save_result(path, domain, expires, days_left):
    conn = sqlite3.connect(path)
    conn.execute("INSERT INTO results(domain,expires,days_left,checked_at) VALUES(?,?,?,datetime('now'))",
                 (domain, expires, days_left))
    conn.commit(); conn.close()

def get_latest_results(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
        SELECT domain, expires, days_left, MAX(checked_at)
        FROM results GROUP BY domain
    """)
    rows = cur.fetchall(); conn.close()
    data = []
    for r in rows:
        data.append({"domain": r[0], "expires": r[1], "days_left": r[2], "checked_at": r[3]})
    return data

def prune_old_results(path):
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM results WHERE checked_at < DATETIME('now','-180 days')")
    conn.commit()
    conn.close()
