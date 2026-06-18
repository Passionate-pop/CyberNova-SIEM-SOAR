"""
Comprehensive tests for CyberNova AI RAG Service.

Tests cover:
  - Document indexing (POST /api/rag/index)
  - Search / query (GET /api/rag/search)
  - Document deletion (DELETE /api/rag/{doc_id})
  - Persistence to disk (rag_store.json)
  - Reload from disk (simulating restart)
  - Stats endpoint (GET /api/rag/stats)
  - Restart recovery
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Generator

import pytest
import pytest_asyncio


@pytest.fixture
def rag_persist_dir() -> Generator:
    """Point RAG to a fresh temp directory for each test (function-scoped)."""
    with tempfile.TemporaryDirectory(prefix="rag_test_") as tmpdir:
        old_val = os.environ.get("RAG_PERSIST_DIR")
        os.environ["RAG_PERSIST_DIR"] = tmpdir
        yield tmpdir
        if old_val is not None:
            os.environ["RAG_PERSIST_DIR"] = old_val
        else:
            os.environ.pop("RAG_PERSIST_DIR", None)


@pytest_asyncio.fixture
async def rag_service(rag_persist_dir) -> Any:
    """Create a fresh RAGService instance for each test."""
    from cybernova.ai.rag import RAGService
    svc = RAGService(persist_dir=rag_persist_dir)
    return svc


# ── Tests ─────────────────────────────────────────────────────────────────


class TestRAGIndexing:
    """Document indexing tests."""

    @pytest.mark.asyncio
    async def test_index_single_document(self, rag_service) -> None:
        chunks = await rag_service.index_document(
            doc_id="test-doc-1",
            content="This is a test document about cybersecurity threats and malware analysis.",
        )
        assert chunks >= 1, "Should have indexed at least one chunk"
        assert len(rag_service._chunks) >= 1
        assert rag_service._chunks[0].doc_id == "test-doc-1"

    @pytest.mark.asyncio
    async def test_index_empty_document_returns_zero(self, rag_service) -> None:
        chunks = await rag_service.index_document(doc_id="empty", content="")
        assert chunks == 0, "Empty content should not be indexed"

    @pytest.mark.asyncio
    async def test_index_empty_doc_id_returns_zero(self, rag_service) -> None:
        chunks = await rag_service.index_document(doc_id="", content="some content")
        assert chunks == 0, "Empty doc_id should not be indexed"

    @pytest.mark.asyncio
    async def test_index_multiple_documents(self, rag_service) -> None:
        await rag_service.index_document("doc-a", "Content A about network security.")
        await rag_service.index_document("doc-b", "Content B about endpoint detection.")
        await rag_service.index_document("doc-c", "Content C about cloud security.")

        docs = rag_service.list_documents()
        assert len(docs) == 3
        doc_ids = {d["doc_id"] for d in docs}
        assert doc_ids == {"doc-a", "doc-b", "doc-c"}

    @pytest.mark.asyncio
    async def test_index_large_document_chunks_correctly(self, rag_service) -> None:
        words = ["word"] * 1200
        content = " ".join(words)
        chunks = await rag_service.index_document(doc_id="large-doc", content=content)
        assert chunks >= 2, "Large document should be split into multiple chunks"
        assert chunks <= 5, "Chunking should not over-split"


class TestRAGPersistence:
    """Persistence tests — verify data survives disk writes."""

    @pytest.mark.asyncio
    async def test_persist_creates_file(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="persist-test",
            content="Test content for persistence verification.",
        )
        store_path = rag_service._store_path()
        assert store_path.exists(), f"rag_store.json should exist at {store_path}"
        data = json.loads(store_path.read_text())
        assert len(data) > 0, "Persisted data should contain chunks"

    @pytest.mark.asyncio
    async def test_persist_and_reload(self, rag_service, rag_persist_dir) -> None:
        """Index a document, create a new RAGService, verify data is loaded."""
        await rag_service.index_document(
            doc_id="reload-test",
            content="Content that should survive reload.",
        )
        chunks_before = len(rag_service._chunks)

        # Simulate restart — create a new RAGService pointing to same dir
        from cybernova.ai.rag import RAGService
        new_service = RAGService(persist_dir=rag_persist_dir)

        assert len(new_service._chunks) == chunks_before, (
            f"Expected {chunks_before} chunks after reload, got {len(new_service._chunks)}"
        )
        doc_ids = {c.doc_id for c in new_service._chunks}
        assert "reload-test" in doc_ids, "Reloaded service should contain indexed doc"

    @pytest.mark.asyncio
    async def test_multiple_persist_and_reload(self, rag_service, rag_persist_dir) -> None:
        """Index multiple documents, reload, verify all survive."""
        await rag_service.index_document("multi-1", "First document content.")
        await rag_service.index_document("multi-2", "Second document content.")
        await rag_service.index_document("multi-3", "Third document content.")

        from cybernova.ai.rag import RAGService
        new_service = RAGService(persist_dir=rag_persist_dir)

        assert len(new_service.list_documents()) == 3
        doc_ids = {d["doc_id"] for d in new_service.list_documents()}
        assert doc_ids == {"multi-1", "multi-2", "multi-3"}

    @pytest.mark.asyncio
    async def test_empty_store_persists_gracefully(self, rag_service, rag_persist_dir) -> None:
        """No documents indexed — no file created, reload is clean."""
        store_path = rag_service._store_path()
        assert not store_path.exists(), "No file should exist before indexing"
        assert rag_service.stats()["total_chunks"] == 0

        from cybernova.ai.rag import RAGService
        new_service = RAGService(persist_dir=rag_persist_dir)
        assert new_service.stats()["total_chunks"] == 0


class TestRAGSearch:
    """Search / query tests."""

    @pytest.mark.asyncio
    async def test_search_existing_content(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="search-doc",
            content="Network intrusion detection systems monitor traffic patterns.",
        )
        result = await rag_service.query(question="intrusion detection")
        assert "answer" in result
        assert len(result["results"]) > 0

    @pytest.mark.asyncio
    async def test_search_empty_knowledge_base(self, rag_service) -> None:
        """Querying with no indexed docs returns a clear message."""
        result = await rag_service.query(question="anything")
        assert result["answer"] == "No indexed documents in knowledge base."
        assert result["sources"] == []

    @pytest.mark.asyncio
    async def test_search_returns_scored_results(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="score-test",
            content="Firewall policies and access control lists.",
        )
        result = await rag_service.query(question="firewall", top_k=5)
        if result["results"]:
            assert "score" in result["results"][0]
            assert result["results"][0]["score"] >= 0.0

    @pytest.mark.asyncio
    async def test_search_top_k_limits_results(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="topk-test",
            content="A B C D E F G H I J K L M N O P Q R S T U V W X Y Z. " * 50,
        )
        result = await rag_service.query(question="test", top_k=2)
        assert len(result["results"]) <= 2

    @pytest.mark.asyncio
    async def test_search_with_metadata_filter(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="filtered-doc",
            content="Critical vulnerability in authentication module.",
            metadata={"severity": "critical", "source": "cve"},
        )
        await rag_service.index_document(
            doc_id="other-doc",
            content="Minor logging improvement.",
            metadata={"severity": "low", "source": "internal"},
        )
        result = await rag_service.query(
            question="vulnerability",
            top_k=5,
            metadata_filter={"severity": "critical"},
        )
        if result["results"]:
            source_docs = {r["doc_id"] for r in result["results"]}
            assert "other-doc" not in source_docs or len(source_docs) == 0


class TestRAGDelete:
    """Document deletion tests."""

    @pytest.mark.asyncio
    async def test_delete_existing_document(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="delete-me",
            content="This document will be deleted.",
        )
        assert rag_service.stats()["total_documents"] == 1

        removed = rag_service.delete_document("delete-me")
        assert removed > 0, "Should have removed chunks"
        assert rag_service.stats()["total_documents"] == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_document_returns_zero(self, rag_service) -> None:
        removed = rag_service.delete_document("does-not-exist")
        assert removed == 0

    @pytest.mark.asyncio
    async def test_delete_persists_to_disk(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="persist-delete",
            content="Will be deleted and verified on disk.",
        )
        rag_service.delete_document("persist-delete")

        store_path = rag_service._store_path()
        if store_path.exists():
            data = json.loads(store_path.read_text())
            for chunk in data:
                assert chunk["doc_id"] != "persist-delete", (
                    "Deleted document should not appear on disk"
                )

    @pytest.mark.asyncio
    async def test_delete_updates_stats(self, rag_service) -> None:
        await rag_service.index_document("stat-1", "First doc.")
        await rag_service.index_document("stat-2", "Second doc.")
        assert rag_service.stats()["total_documents"] == 2

        rag_service.delete_document("stat-1")
        stats = rag_service.stats()
        assert stats["total_documents"] == 1
        assert stats["total_chunks"] >= 1


class TestRAGRestartRecovery:
    """Restart recovery tests — simulate full application restart."""

    @pytest.mark.asyncio
    async def test_data_survives_full_restart(self, rag_persist_dir) -> None:
        """Index, destroy service, recreate from same dir."""
        from cybernova.ai.rag import RAGService

        svc = RAGService(persist_dir=rag_persist_dir)
        await svc.index_document(
            doc_id="restart-doc",
            content="Data that must survive a full restart.",
            metadata={"source": "restart-test"},
        )
        chunks_first = svc.stats()["total_chunks"]

        del svc
        svc2 = RAGService(persist_dir=rag_persist_dir)
        assert svc2.stats()["total_chunks"] == chunks_first, (
            f"Chunks after restart: {svc2.stats()['total_chunks']} vs {chunks_first}"
        )
        assert svc2.stats()["total_documents"] == 1

        result = await svc2.query(question="restart")
        assert result["answer"] != "No indexed documents in knowledge base."

    @pytest.mark.asyncio
    async def test_multiple_restarts_preserve_data(self, rag_persist_dir) -> None:
        """Multiple restart cycles should preserve all data."""
        from cybernova.ai.rag import RAGService

        svc1 = RAGService(persist_dir=rag_persist_dir)
        await svc1.index_document("persist-1", "Content from first session.")
        del svc1

        svc2 = RAGService(persist_dir=rag_persist_dir)
        await svc2.index_document("persist-2", "Content from second session.")
        assert len(svc2.list_documents()) == 2
        del svc2

        svc3 = RAGService(persist_dir=rag_persist_dir)
        assert len(svc3.list_documents()) == 2
        doc_ids = {d["doc_id"] for d in svc3.list_documents()}
        assert doc_ids == {"persist-1", "persist-2"}

    @pytest.mark.asyncio
    async def test_restart_with_deleted_docs(self, rag_persist_dir) -> None:
        """Delete a doc, restart, verify it's gone."""
        from cybernova.ai.rag import RAGService

        svc = RAGService(persist_dir=rag_persist_dir)
        await svc.index_document("delete-before-restart", "Will be deleted.")
        svc.delete_document("delete-before-restart")
        del svc

        svc2 = RAGService(persist_dir=rag_persist_dir)
        assert svc2.stats()["total_documents"] == 0


class TestRAGAPI:
    """API endpoint tests using TestClient — each test gets a fresh app + isolated RAG."""

    @pytest.fixture
    def isolated_rag(self, rag_persist_dir) -> Any:
        """Create an isolated RAG service for API tests, patched into the router module."""
        from cybernova.ai.rag import RAGService
        svc = RAGService(persist_dir=rag_persist_dir)
        return svc

    def _mock_user(self) -> Any:
        """Create a mock admin user for auth overrides."""
        from cybernova.security.encryption.jwt_handler import CurrentUser
        return CurrentUser(
            id="test-user",
            tenant_id="default",
            username="test-admin",
            roles=["admin"],
        )

    @pytest.fixture
    def client(self, isolated_rag):
        """Create a minimal FastAPI app with only the RAG router, using isolated RAG service."""
        from fastapi import FastAPI, Depends
        from fastapi.testclient import TestClient
        import cybernova.ai.rag as rag_mod

        # Save original and patch with isolated service
        original = rag_mod.rag_service
        rag_mod.rag_service = isolated_rag

        app = FastAPI()
        from cybernova.ai.rag.router import router as rag_router

        # Override auth dependencies with a mock admin user
        mock_user = self._mock_user()

        async def _override_get_user():
            return mock_user

        from cybernova.security.encryption.jwt_handler import get_current_user
        from cybernova.auth.dependencies import require_rag_view, require_rag_manage

        app.dependency_overrides[get_current_user] = _override_get_user
        app.dependency_overrides[require_rag_view] = _override_get_user
        app.dependency_overrides[require_rag_manage] = _override_get_user

        app.include_router(rag_router)

        tc = TestClient(app)
        yield tc

        # Restore
        rag_mod.rag_service = original

    def test_post_index(self, client) -> None:
        resp = client.post(
            "/api/rag/index",
            json={"doc_id": "api-test-doc", "content": "API test document content for RAG."},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["status"] == "ok"
        assert data["doc_id"] == "api-test-doc"
        assert data["chunks_indexed"] >= 1

    def test_get_stats(self, client) -> None:
        resp = client.get("/api/rag/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_chunks" in data
        assert "total_documents" in data
        assert "persist_dir" in data

    def test_search_endpoint(self, client) -> None:
        client.post(
            "/api/rag/index",
            json={"doc_id": "search-test", "content": "This is content about network security monitoring."},
        )
        resp = client.get("/api/rag/search", params={"q": "network security", "top_k": 3})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert "answer" in data
        assert "results" in data

    def test_search_empty_knowledge_base(self, client) -> None:
        """Searching with no indexed docs returns a graceful response."""
        resp = client.get("/api/rag/search", params={"q": "something"})
        assert resp.status_code == 200
        data = resp.json()
        assert "answer" in data
        assert data["answer"] == "No indexed documents in knowledge base."

    def test_search_missing_query_returns_422(self, client) -> None:
        resp = client.get("/api/rag/search")
        assert resp.status_code == 422  # FastAPI validation error for missing required query param

    def test_delete_document(self, client) -> None:
        client.post(
            "/api/rag/index",
            json={"doc_id": "delete-me-api", "content": "Will be deleted via API."},
        )
        resp = client.delete("/api/rag/delete-me-api")
        assert resp.status_code == 200
        data = resp.json()
        assert data["doc_id"] == "delete-me-api"
        assert data["chunks_removed"] >= 1

    def test_delete_nonexistent_returns_404(self, client) -> None:
        resp = client.delete("/api/rag/does-not-exist")
        assert resp.status_code == 404
        assert "not found" in resp.text.lower()

    def test_list_documents(self, client) -> None:
        resp = client.get("/api/rag/documents")
        assert resp.status_code == 200
        data = resp.json()
        assert "documents" in data
        assert "total" in data

    def test_full_workflow(self, client) -> None:
        """End-to-end: index → stats → search → list → delete → stats."""
        r1 = client.post(
            "/api/rag/index",
            json={"doc_id": "e2e", "content": "End-to-end test document for complete workflow validation."},
        )
        assert r1.status_code == 200

        r2 = client.get("/api/rag/stats")
        assert r2.json()["total_documents"] == 1

        r3 = client.get("/api/rag/search", params={"q": "workflow validation"})
        assert r3.status_code == 200

        r4 = client.get("/api/rag/documents")
        assert r4.json()["total"] == 1

        r5 = client.delete("/api/rag/e2e")
        assert r5.status_code == 200

        r6 = client.get("/api/rag/stats")
        assert r6.json()["total_documents"] == 0

    def test_post_index_empty_doc_id_returns_400(self, client) -> None:
        resp = client.post(
            "/api/rag/index",
            json={"doc_id": "", "content": "some content"},
        )
        assert resp.status_code == 400

    def test_post_index_empty_content_returns_400(self, client) -> None:
        resp = client.post(
            "/api/rag/index",
            json={"doc_id": "doc", "content": ""},
        )
        assert resp.status_code == 400


class TestRAGServiceStats:
    """Stats endpoint and utility tests."""

    @pytest.mark.asyncio
    async def test_stats_empty(self, rag_service) -> None:
        stats = rag_service.stats()
        assert stats["total_chunks"] == 0
        assert stats["total_documents"] == 0
        assert "persist_dir" in stats

    @pytest.mark.asyncio
    async def test_stats_after_indexing(self, rag_service) -> None:
        await rag_service.index_document("stats-1", "Content A")
        await rag_service.index_document("stats-2", "Content B" * 200)

        stats = rag_service.stats()
        assert stats["total_documents"] == 2
        assert stats["total_chunks"] >= 2

    @pytest.mark.asyncio
    async def test_list_documents(self, rag_service) -> None:
        await rag_service.index_document("list-1", "Content A", {"type": "report"})
        await rag_service.index_document("list-2", "Content B")

        docs = rag_service.list_documents()
        assert len(docs) == 2
        for doc in docs:
            assert "doc_id" in doc
            assert "chunks" in doc
            assert "metadata" in doc


class TestRAGEdgeCases:
    """Edge case tests."""

    @pytest.mark.asyncio
    async def test_special_characters_in_content(self, rag_service) -> None:
        await rag_service.index_document(
            doc_id="special-chars",
            content="Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~ 你好 português español",
        )
        assert rag_service.stats()["total_documents"] == 1

    @pytest.mark.asyncio
    async def test_very_large_metadata(self, rag_service) -> None:
        large_meta = {"key" + str(i): "value" + str(i) for i in range(100)}
        await rag_service.index_document(
            doc_id="large-meta",
            content="Document with large metadata.",
            metadata=large_meta,
        )
        assert rag_service.stats()["total_documents"] == 1

    @pytest.mark.asyncio
    async def test_index_same_doc_id_twice(self, rag_service) -> None:
        """Indexing same doc_id adds more chunks (doesn't replace)."""
        c1 = await rag_service.index_document("duplicate", "First version.")
        c2 = await rag_service.index_document("duplicate", "Second version.")
        assert rag_service.stats()["total_documents"] == 1
        doc = [d for d in rag_service.list_documents() if d["doc_id"] == "duplicate"][0]
        assert doc["chunks"] == c1 + c2

    @pytest.mark.asyncio
    async def test_empty_query_returns_graceful_response(self, rag_service) -> None:
        """Searching with no chunks returns a clear message."""
        result = await rag_service.query(question="anything")
        assert result["answer"] == "No indexed documents in knowledge base."
        assert result["sources"] == []
