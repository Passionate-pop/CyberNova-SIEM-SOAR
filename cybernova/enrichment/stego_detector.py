"""
CyberNova — Steganography Detector
LSB plane analysis, EXIF metadata anomalies, palette-based stego detection.
Async, pure-Python (Pillow for image I/O), designed as an enrichment step.
"""
from __future__ import annotations

import asyncio
import io
import logging
from typing import Any, Dict

try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

log = logging.getLogger("cybernova.enrichment.stego_detector")


class StegoDetector:

    async def analyze(self, image_data: bytes, filename: str = "") -> Dict[str, Any]:
        if not HAS_PILLOW:
            return {"error": "Pillow not installed", "stego_suspected": False}
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._analyze_sync, image_data, filename)

    def _analyze_sync(self, image_data: bytes, filename: str = "") -> Dict[str, Any]:
        if not HAS_PILLOW:
            return {"error": "Pillow not installed", "stego_suspected": False}
        result = {
            "filename": filename,
            "format": None,
            "stego_suspected": False,
            "risk_score": 0.0,
            "findings": [],
        }
        try:
            img = Image.open(io.BytesIO(image_data))
            result["format"] = img.format
            result["mode"] = img.mode
            result["size"] = img.size

            for check in (self._lsb, self._metadata, self._palette):
                r = check(img, image_data)
                if r.get("suspicious"):
                    result["findings"].append(r)
                    result["stego_suspected"] = True
                    result["risk_score"] = max(result["risk_score"], r.get("risk_score", 0))
        except Exception as e:
            log.error("Stego analysis failed: %s", e)
            result["error"] = str(e)
        return result

    # ── LSB plane analysis ──────────────────────────────────────────────────

    def _lsb(self, img: Image.Image, _raw: bytes) -> Dict[str, Any]:
        res: Dict[str, Any] = {"type": "lsb_analysis", "suspicious": False, "risk_score": 0.0, "details": {}}
        if img.mode not in ("RGB", "RGBA"):
            return res

        pixels = list(img.getdata())
        width, height = img.size
        channels = 3 if img.mode == "RGB" else 4

        lsb_bits = []
        for pixel in pixels[:5000]:
            for c in range(min(channels, 3)):
                lsb_bits.append(pixel[c] & 1)

        if not lsb_bits:
            return res

        ones = sum(lsb_bits)
        len(lsb_bits) - ones
        ratio = ones / len(lsb_bits) if lsb_bits else 0.5

        runs = 1
        for i in range(1, len(lsb_bits)):
            if lsb_bits[i] != lsb_bits[i - 1]:
                runs += 1

        expected_runs = len(lsb_bits) / 2
        run_ratio = runs / expected_runs if expected_runs else 1.0

        res["details"] = {"samples": len(lsb_bits), "lsb_ones_ratio": round(ratio, 4), "run_ratio": round(run_ratio, 4)}

        if abs(ratio - 0.5) < 0.005:
            res["suspicious"] = True
            res["risk_score"] = 65.0
            res["details"]["anomaly"] = "LSB distribution too uniform (50/50)"
            res["details"]["anomaly_type"] = "uniform_lsb"
        elif ratio < 0.1 or ratio > 0.9:
            res["suspicious"] = True
            res["risk_score"] = 70.0
            res["details"]["anomaly"] = f"LSB extremely biased ({ratio:.1%} ones)"
            res["details"]["anomaly_type"] = "biased_lsb"

        if run_ratio < 0.8 or run_ratio > 1.2:
            res["suspicious"] = True
            res["risk_score"] = max(res["risk_score"], 60.0)
            res["details"]["anomaly"] = f"Abnormal LSB run distribution ({run_ratio:.2f})"
            res["details"]["anomaly_type"] = "lsb_run_anomaly"

        return res

    # ── EXIF / metadata anomalies ───────────────────────────────────────────

    def _metadata(self, img: Image.Image, raw_data: bytes) -> Dict[str, Any]:
        res: Dict[str, Any] = {"type": "metadata_anomaly", "suspicious": False, "risk_score": 0.0, "details": {}}

        exif_bytes = img.info.get("exif", b"")
        res["details"]["has_exif"] = bool(exif_bytes)
        if not exif_bytes:
            return res

        res["details"]["exif_size"] = len(exif_bytes)

        try:
            exif = img._getexif() if hasattr(img, "_getexif") else None
        except Exception as e:
            log.warning("Failed to read EXIF data: %s", e)
            exif = None

        if exif is None:
            return res

        gps_tags = [t for t in exif if isinstance(t, int) and 34853 <= t <= 34867]
        if gps_tags:
            res["suspicious"] = True
            res["risk_score"] = 50.0
            res["details"]["anomaly"] = "GPS coordinates in image metadata"
            res["details"]["anomaly_type"] = "gps_metadata"
            res["details"]["has_gps"] = True

        if len(exif_bytes) > 50000:
            res["suspicious"] = True
            res["risk_score"] = max(res["risk_score"], 55.0)
            res["details"]["anomaly"] = f"Oversized EXIF block ({len(exif_bytes)} bytes)"
            res["details"]["anomaly_type"] = "oversized_exif"
            res["details"]["exif_too_large"] = True

        thumb_width = exif.get(513)
        thumb_height = exif.get(514)
        if thumb_width == 0 and thumb_height == 0:
            res["suspicious"] = True
            res["risk_score"] = max(res["risk_score"], 60.0)
            res["details"]["anomaly"] = "Zero-size thumbnail in EXIF"
            res["details"]["anomaly_type"] = "zero_thumbnail"
            res["details"]["zero_thumbnail"] = True

        maker_note = exif.get(37500)
        if maker_note and len(str(maker_note)) > 1000:
            res["suspicious"] = True
            res["risk_score"] = max(res["risk_score"], 45.0)
            res["details"]["anomaly"] = f"Large MakerNote ({len(str(maker_note))} chars)"
            res["details"]["anomaly_type"] = "large_maker_notes"
            res["details"]["large_maker_notes"] = True

        if img.format == "PNG":
            for key in ("text", "tEXt", "zTXt", "iTXt"):
                val = img.info.get(key)
                if val and len(str(val)) > 200:
                    res["suspicious"] = True
                    res["risk_score"] = max(res["risk_score"], 55.0)
                    res["details"]["anomaly"] = f"Large PNG text chunk '{key}' ({len(str(val))} chars)"
                    res["details"]["anomaly_type"] = "large_png_text_chunk"
                    res["details"]["large_text_chunk"] = True

        return res

    # ── Palette analysis (BMP / PNG-8) ──────────────────────────────────────

    def _palette(self, img: Image.Image, _raw: bytes) -> Dict[str, Any]:
        res: Dict[str, Any] = {"type": "palette_anomaly", "suspicious": False, "risk_score": 0.0, "details": {}}
        if not hasattr(img, "palette") or img.palette is None:
            return res
        if img.mode != "P":
            return res

        pal = img.palette
        pdata = pal.data if hasattr(pal, "data") else b""
        if not pdata:
            return res

        res["details"]["palette_colors"] = len(pdata) // 3

        seen: Dict[tuple, int] = {}
        dups = []
        for i in range(0, len(pdata), 3):
            if i + 2 >= len(pdata):
                break
            color = (pdata[i], pdata[i + 1], pdata[i + 2])
            idx = i // 3
            if color in seen:
                dups.append({"index": idx, "duplicate_of": seen[color], "color": str(color)})
            else:
                seen[color] = idx

        if dups:
            res["suspicious"] = True
            res["risk_score"] = 55.0
            res["details"]["duplicate_colors"] = len(dups)
            res["details"]["duplicate_color_indices"] = [d["index"] for d in dups[:10]]
            res["details"]["anomaly"] = f"Duplicate palette entries ({len(dups)} colors)"
            res["details"]["anomaly_type"] = "duplicate_palette_entries"

        return res


stego_detector = StegoDetector()
