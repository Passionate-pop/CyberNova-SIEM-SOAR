#!/usr/bin/env python3
"""Convert CyberNova logo.png to a multi-size .ico file for Windows desktop shortcuts."""
import sys
import struct
import io
from pathlib import Path

def png_to_ico(png_path: str, ico_path: str):
    """Convert PNG to ICO. Uses Pillow if available, otherwise falls back to raw ICO with embedded PNG."""
    try:
        from PIL import Image
        img = Image.open(png_path).convert('RGBA')
        sizes = [16, 32, 48, 64, 128, 256]
        resized = []
        for s in sizes:
            r = img.resize((s, s), Image.LANCZOS)
            resized.append(r)
        
        Path(ico_path).parent.mkdir(parents=True, exist_ok=True)
        resized[0].save(
            ico_path,
            format='ICO',
            sizes=[(s, s) for s in sizes],
            append_images=resized[1:]
        )
        print(f"Created ICO from logo.png (Pillow): {ico_path}")
        return True
    except ImportError:
        pass
    
    # Fallback: embed the raw PNG inside an ICO container (no Pillow needed)
    png_data = Path(png_path).read_bytes()
    # Read PNG dimensions
    if png_data[16:17] == b'\x00':
        w = struct.unpack('>H', png_data[16:18])[0]
        h = struct.unpack('>H', png_data[18:20])[0]
    else:
        w, h = 256, 256  # PNG spec: 0 means 256
    
    ico = io.BytesIO()
    # ICONDIR
    ico.write(struct.pack('<HHH', 0, 1, 1))
    # ICONDIRENTRY (PNG-compressed)
    data_offset = 6 + 16
    ico.write(struct.pack('<BBBBHHII', w & 0xFF, h & 0xFF, 0, 0, 1, 32, len(png_data), data_offset))
    # PNG data
    ico.write(png_data)
    
    Path(ico_path).parent.mkdir(parents=True, exist_ok=True)
    with open(ico_path, 'wb') as f:
        f.write(ico.getvalue())
    print(f"Created ICO from logo.png (embedded PNG): {ico_path}")
    return True


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.png> <output.ico>")
        sys.exit(1)
    png_to_ico(sys.argv[1], sys.argv[2])
