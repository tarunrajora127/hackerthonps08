"""Initialize AGENTGATE SQLite database and verify schema creation."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agentgate.db.database import AgentGateDB

def main():
    db_file = Path(__file__).parent / "agentgate.db"
    print(f"Initializing database at: {db_file}")
    db = AgentGateDB(str(db_file))
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"Verified tables ({len(tables)}): {tables}")
        
    print("Database initialization complete.")

if __name__ == "__main__":
    main()

