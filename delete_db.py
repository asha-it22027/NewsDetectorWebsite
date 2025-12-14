
import os

db_path = 'app.db'
if os.path.exists(db_path):
    try:
        os.remove(db_path)
        print(f"Successfully deleted {db_path}")
    except Exception as e:
        print(f"Error deleting {db_path}: {e}")
else:
    print(f"{db_path} does not exist.")
