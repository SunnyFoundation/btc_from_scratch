python3 - <<'PY'
from io import BytesIO
from Block import Block
from pathlib import Path

blocks = []
path = Path("genesis_block.bin")
if path.exists():
    data = path.read_bytes()
    for offset in range(0, len(data), 80):
        chunk = data[offset:offset+80]
        if len(chunk) < 80:
            break
        blocks.append(Block.parse(BytesIO(chunk)))
print(f"chain length: {len(blocks)}")
for height, block in enumerate(blocks):
    print(height, block.hash().hex())
PY