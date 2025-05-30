import hashlib
import numpy as np
import pandas as pd

def custom_md5_hash_vector(parts, n_features=10, missing="nan"):
    vec = np.zeros(n_features, dtype=np.float32)
    for raw in parts:
        text = str(raw) if pd.notna(raw) else missing
        digest = hashlib.md5(text.encode()).digest()
        int_hash = int.from_bytes(digest[:4], byteorder='little', signed=False)
        index = int_hash % n_features
        sign = -1 if int_hash & 1 else 1
        vec[index] += sign
    return vec

# בדיקה
parts = ["www.amazon.com", "GlobalSign nv-sa", "Amazon Registrar, Inc."]
output = custom_md5_hash_vector(parts)
print("✅ MD5-compatible hash:", list(output))
