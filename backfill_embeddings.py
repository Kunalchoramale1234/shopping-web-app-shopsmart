# tools/backfill_embeddings.py (run manually)
import json, os, numpy as np
from mysql.connector import connect
from sentence_transformers import SentenceTransformer
import os




os.environ["USE_TF"] = "0"   # disable TensorFlow, only use PyTorch
os.environ["USE_TORCH"] = "1"  # force PyTorch backend

DB = dict(
    host="localhost", user="root", password="Kunal$21", database="shopping_app", port=3306
)

def main():
    model = SentenceTransformer("msmarco-bert-base-dot-v5")
    conn = connect(**DB)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, name, description FROM products")
    rows = cur.fetchall()

    insert = conn.cursor()
    for r in rows:
        text = f"{r['name']}. {r.get('description') or ''}".strip()
        vec = model.encode([text], normalize_embeddings=True)[0].astype("float32")
        blob = vec.tobytes()
        dim = vec.shape[0]
        insert.execute("""
            INSERT INTO product_embeddings (product_id, vector, dim)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE vector=VALUES(vector), dim=VALUES(dim)
        """, (r['id'], blob, dim))
    conn.commit()
    insert.close(); cur.close(); conn.close()
    print(f"Indexed {len(rows)} products.")

if __name__ == "__main__":
    main()
