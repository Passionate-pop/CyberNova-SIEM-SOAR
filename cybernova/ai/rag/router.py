"""
RAG API router. Index, search, and manage documents in the knowledge base.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.auth.dependencies import require_rag_view, require_rag_manage

import cybernova.ai.rag as _rag_mod

log = logging.getLogger("cybernova.ai.rag.router")

# NOTE: All endpoint functions use _rag_mod.rag_service (not a cached local variable)
# so that tests can patch cybernova.ai.rag.rag_service for isolation.

router = APIRouter(prefix="/api/rag", tags=["RAG Knowledge Base"])


# models


class IndexRequest(BaseModel):
    doc_id: str
    content: str
    metadata: Optional[Dict[str, Any]] = None


class DeleteResponse(BaseModel):
    doc_id: str
    chunks_removed: int


class StatsResponse(BaseModel):
    total_chunks: int
    total_documents: int
    persist_dir: str


# endpoints


def _get_rag():
    """Return the current rag_service (looked up dynamically for testability)."""
    return _rag_mod.rag_service


@router.post("/index", summary="Index a document into the RAG knowledge base")
async def index_document(
    request: IndexRequest,
    user: CurrentUser = Depends(require_rag_manage),
) -> Dict[str, Any]:
    """
    Index a document into the RAG knowledge base.

    The document is chunked, embedded, and persisted to disk.
    """
    if not request.doc_id.strip():
        raise HTTPException(status_code=400, detail="doc_id must not be empty")
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="content must not be empty")

    svc = _get_rag()
    chunks = await svc.index_document(
        doc_id=request.doc_id,
        content=request.content,
        metadata=request.metadata or {},
    )
    return {
        "status": "ok",
        "doc_id": request.doc_id,
        "chunks_indexed": chunks,
    }


@router.get("/search", summary="Search the RAG knowledge base")
async def search(
    q: str = Query(..., description="Search query"),
    top_k: int = Query(3, description="Number of results to return"),
    user: CurrentUser = Depends(require_rag_view),
) -> Dict[str, Any]:
    """
    Search the RAG knowledge base with a natural language query.

    Returns an AI-generated answer along with source documents.
    """
    if not q.strip():
        raise HTTPException(status_code=400, detail="Query parameter 'q' must not be empty")
    if top_k < 1 or top_k > 50:
        raise HTTPException(status_code=400, detail="top_k must be between 1 and 50")

    svc = _get_rag()
    result = await svc.query(question=q, top_k=top_k)
    return result


@router.delete("/{doc_id}", summary="Delete a document from the RAG knowledge base")
async def delete_document(
    doc_id: str,
    user: CurrentUser = Depends(require_rag_manage),
) -> DeleteResponse:
    """
    Delete a document and all its chunks from the RAG knowledge base.
    """
    svc = _get_rag()
    chunks_removed = svc.delete_document(doc_id)
    if chunks_removed == 0:
        raise HTTPException(
            status_code=404,
            detail=f"Document '{doc_id}' not found in RAG knowledge base",
        )
    return DeleteResponse(doc_id=doc_id, chunks_removed=chunks_removed)


@router.get("/stats", summary="Get RAG knowledge base statistics")
async def stats(
    user: CurrentUser = Depends(require_rag_view),
) -> StatsResponse:
    """Get statistics about the RAG knowledge base (total chunks, documents, persist dir)."""
    s = _get_rag().stats()
    return StatsResponse(**s)


@router.get("/documents", summary="List all documents in the RAG knowledge base")
async def list_documents(
    user: CurrentUser = Depends(require_rag_view),
) -> Dict[str, Any]:
    """List all documents that have been indexed into the RAG knowledge base."""
    docs = _get_rag().list_documents()
    return {"documents": docs, "total": len(docs)}
