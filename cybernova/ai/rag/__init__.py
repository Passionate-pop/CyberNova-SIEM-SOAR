"""
AI RAG service. Vector store with chunking, cosine search, metadata filtering, disk persistence.
"""
from __future__ import annotations

import json
import logging
import math
import os
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from cybernova.ai.base import get_llm_provider

log = logging.getLogger("cybernova.ai.rag")

PERSIST_DIR = os.environ.get("RAG_PERSIST_DIR", "/data/rag_store")
CHUNK_SIZE = 512
CHUNK_OVERLAP = 64


@dataclass
class DocumentChunk:
    id: str = ""
    doc_id: str = ""
    content: str = ""
    embedding: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    chunk_index: int = 0


@dataclass
class SearchResult:
    chunk: DocumentChunk
    score: float = 0.0


class RAGService:
    """RAG with persistent vector storage."""

    def __init__(self, persist_dir: str = PERSIST_DIR) -> None:
        self._provider = get_llm_provider()
        self._persist_dir = Path(persist_dir)
        self._persist_dir.mkdir(parents=True, exist_ok=True)
        self._chunks: List[DocumentChunk] = []
        self._load()

    # persistence

    def _store_path(self) -> Path:
        return self._persist_dir / "rag_store.json"

    def _save(self) -> None:
        path = self._store_path()
        try:
            self._persist_dir.mkdir(parents=True, exist_ok=True)
            data = [asdict(c) for c in self._chunks]
            path.write_text(json.dumps(data, indent=2))
            log.info("RAG: saved %d chunks to %s", len(self._chunks), path)
        except Exception as exc:
            log.error("RAG: failed to save store at %s: %s", path, exc)

    def _load(self) -> None:
        path = self._store_path()
        if not path.exists():
            log.info("RAG: no persisted store found at %s", path)
            return
        try:
            data = json.loads(path.read_text())
            for item in data:
                self._chunks.append(DocumentChunk(**item))
            log.info("RAG: loaded %d chunks from disk", len(self._chunks))
        except Exception as exc:
            log.warning("RAG: failed to load persisted store: %s", exc)

    # chunking

    def _chunk_text(self, content: str) -> List[str]:
        if not content:
            return []
        words = content.split()
        if len(words) <= CHUNK_SIZE:
            return [content]

        chunks: List[str] = []
        step = CHUNK_SIZE - CHUNK_OVERLAP
        for i in range(0, len(words), step):
            chunk_words = words[i:i + CHUNK_SIZE]
            chunks.append(" ".join(chunk_words))
            if i + CHUNK_SIZE >= len(words):
                break
        return chunks

    # embedding

    async def _embed(self, text: str) -> List[float]:
        try:
            result = await self._provider.embed(text)
            if result and any(v != 0.0 for v in result[:10]):
                log.debug("RAG: embedding success (%d dimensions)", len(result))
            else:
                log.warning("RAG: embedding returned all-zeros for: %.60s...", text)
            return result
        except Exception as exc:
            log.error("RAG: embedding failed: %s", exc)
            return [0.0] * 384

    # cosine similarity

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        if not a or not b:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (na * nb)

    # indexing

    async def index_document(
        self,
        doc_id: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        if not doc_id or not content:
            log.warning("RAG: skipping empty document %s", doc_id)
            return 0

        metadata = metadata or {}
        chunks_text = self._chunk_text(content)
        log.info("RAG: indexing document %s (%d chars, %d chunks)", doc_id, len(content), len(chunks_text))

        count = 0
        for idx, chunk_text in enumerate(chunks_text):
            embedding = await self._embed(chunk_text)
            chunk = DocumentChunk(
                id=str(uuid.uuid4()),
                doc_id=doc_id,
                content=chunk_text,
                embedding=embedding,
                metadata=metadata,
                chunk_index=idx,
            )
            self._chunks.append(chunk)
            count += 1

        self._save()
        log.info("RAG: indexed %d chunks for document %s", count, doc_id)
        return count

    # query / search

    async def query(
        self,
        question: str,
        top_k: int = 3,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self._chunks:
            log.warning("RAG: no indexed documents, returning empty result")
            return {"answer": "No indexed documents in knowledge base.", "sources": []}

        query_embedding = await self._embed(question)
        results = self._search(query_embedding, top_k=top_k, metadata_filter=metadata_filter)

        if not results:
            return {"answer": "No relevant documents found.", "sources": []}

        context = "\n\n".join(r.chunk.content for r in results)
        sources = list({r.chunk.doc_id for r in results})

        prompt = (
            f"Based on this security knowledge base:\n{context}\n\n"
            f"Answer the following question using ONLY the provided context. "
            f"If the context does not contain enough information, say so.\n\n"
            f"Question: {question}"
        )

        try:
            from cybernova.ai.base import get_llm_provider
            provider = get_llm_provider()
            import asyncio
            answer = await asyncio.wait_for(provider.generate(prompt), timeout=15.0)
        except Exception as exc:
            log.error("RAG: LLM generation failed: %s", exc)
            answer = "RAG Error: AI provider unavailable."

        return {
            "answer": answer,
            "sources": sources,
            "results": [
                {"doc_id": r.chunk.doc_id, "score": round(r.score, 4), "content": r.chunk.content[:200]}
                for r in results
            ],
        }

    def _search(
        self,
        query_embedding: List[float],
        top_k: int = 3,
        metadata_filter: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResult]:
        candidates = self._chunks

        if metadata_filter:
            filtered: List[DocumentChunk] = []
            for chunk in candidates:
                match = True
                for key, value in metadata_filter.items():
                    if chunk.metadata.get(key) != value:
                        match = False
                        break
                if match:
                    filtered.append(chunk)
            candidates = filtered
            log.debug("RAG: metadata filter reduced candidates from %d to %d", len(self._chunks), len(candidates))

        scored = []
        for chunk in candidates:
            score = self._cosine_similarity(query_embedding, chunk.embedding)
            scored.append(SearchResult(chunk=chunk, score=score))

        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]

    # document management

    def delete_document(self, doc_id: str) -> int:
        before = len(self._chunks)
        self._chunks = [c for c in self._chunks if c.doc_id != doc_id]
        removed = before - len(self._chunks)
        if removed:
            self._save()
            log.info("RAG: deleted document %s (%d chunks)", doc_id, removed)
        else:
            log.warning("RAG: document %s not found for deletion", doc_id)
        return removed

    def list_documents(self) -> List[Dict[str, Any]]:
        seen: Dict[str, Any] = {}
        for chunk in self._chunks:
            if chunk.doc_id not in seen:
                seen[chunk.doc_id] = {
                    "doc_id": chunk.doc_id,
                    "chunks": 1,
                    "metadata": chunk.metadata,
                }
            else:
                seen[chunk.doc_id]["chunks"] += 1
        return list(seen.values())

    def stats(self) -> Dict[str, Any]:
        return {
            "total_chunks": len(self._chunks),
            "total_documents": len(self.list_documents()),
            "persist_dir": str(self._persist_dir),
        }


rag_service = RAGService()
