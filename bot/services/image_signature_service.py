from __future__ import annotations

import hashlib
from io import BytesIO

from PIL import Image, ImageOps
from motor.motor_asyncio import AsyncIOMotorCollection


class ImageSignatureService:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self._collection = collection

    async def is_known_bitcoin_scam(self, payload: bytes) -> bool:
        exact_signature, a_hash, d_hash = self._compute_signatures(payload)
        if not exact_signature:
            return False

        exact_doc = await self._collection.find_one(
            {
                "label": "bitcoin_scam",
                "exact_signature": exact_signature,
            },
            {"_id": 1},
        )
        if exact_doc is not None:
            return True

        candidate_docs = await self._collection.find(
            {
                "label": "bitcoin_scam",
                "a_hash": {"$exists": True},
                "d_hash": {"$exists": True},
            },
            {"_id": 0, "a_hash": 1, "d_hash": 1},
        ).to_list(length=20000)

        for doc in candidate_docs:
            db_a = doc.get("a_hash")
            db_d = doc.get("d_hash")
            if not isinstance(db_a, str) or not isinstance(db_d, str):
                continue

            a_distance = self._hamming_hex(a_hash, db_a)
            d_distance = self._hamming_hex(d_hash, db_d)

            if a_distance <= 14 and d_distance <= 16:
                return True

        return False

    async def upsert_bitcoin_scam_signature(self, payload: bytes, *, source: str) -> bool:
        exact_signature, a_hash, d_hash = self._compute_signatures(payload)
        if not exact_signature:
            return False

        result = await self._collection.update_one(
            {"label": "bitcoin_scam", "exact_signature": exact_signature},
            {
                "$setOnInsert": {
                    "label": "bitcoin_scam",
                    "source": source,
                    "exact_signature": exact_signature,
                    "a_hash": a_hash,
                    "d_hash": d_hash,
                }
            },
            upsert=True,
        )
        return result.upserted_id is not None

    def _compute_signatures(self, payload: bytes) -> tuple[str | None, str, str]:
        try:
            img = Image.open(BytesIO(payload)).convert("RGB")
            normalized = ImageOps.grayscale(img).resize((16, 16)).tobytes()
            exact_signature = hashlib.sha256(normalized).hexdigest()

            a_hash = self._average_hash(img)
            d_hash = self._difference_hash(img)
            return exact_signature, a_hash, d_hash
        except Exception:
            return None, "", ""

    def _average_hash(self, img: Image.Image) -> str:
        gray = ImageOps.grayscale(img).resize((8, 8))
        pixels = list(gray.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if px >= avg else "0" for px in pixels)
        return f"{int(bits, 2):016x}"

    def _difference_hash(self, img: Image.Image) -> str:
        gray = ImageOps.grayscale(img).resize((9, 8))
        pixels = list(gray.getdata())
        bits = []
        for row in range(8):
            offset = row * 9
            for col in range(8):
                left = pixels[offset + col]
                right = pixels[offset + col + 1]
                bits.append("1" if left > right else "0")
        return f"{int(''.join(bits), 2):016x}"

    def _hamming_hex(self, left: str, right: str) -> int:
        try:
            return (int(left, 16) ^ int(right, 16)).bit_count()
        except ValueError:
            return 64
