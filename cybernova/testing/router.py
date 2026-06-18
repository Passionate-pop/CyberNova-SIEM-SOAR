from __future__ import annotations

import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from cybernova.security.encryption.jwt_handler import CurrentUser
from cybernova.api.dependencies.tenant import get_tenant_id
from cybernova.auth.dependencies import require_testing_view, require_testing_execute
from cybernova.testing.runner import run_single_test, run_all_tests
from cybernova.testing.sigma_validator import validate_sigma_yaml
from cybernova.testing.atomic_tests import ATOMIC_TESTS, get_atomic_test

log = logging.getLogger("cybernova.testing.router")
router = APIRouter(prefix="/api/v1/testing", tags=["Detection Testing"])


class SigmaValidateRequest(BaseModel):
    yaml_content: str


class SigmaValidateResponse(BaseModel):
    valid: bool
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    errors: List[Dict[str, str]] = []
    warnings: List[Dict[str, str]] = []


@router.get("/tests", summary="List all atomic tests")
async def list_tests(
    user: CurrentUser = Depends(require_testing_view),
):
    tests = []
    for t in ATOMIC_TESTS:
        tests.append({
            "id": t["id"],
            "name": t["name"],
            "description": t.get("description", ""),
            "mitre_id": t.get("mitre_id"),
            "mitre_tactic": t.get("mitre_tactic"),
            "target_rule": t.get("target_rule"),
            "expected_match": t.get("expected_match", True),
            "expected_severity": t.get("expected_severity"),
        })
    return {"tests": tests, "total": len(tests)}


@router.post("/run/{test_id}", summary="Run a single atomic test")
async def run_test(
    test_id: str,
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_testing_execute),
):
    test = get_atomic_test(test_id)
    if test is None:
        raise HTTPException(status_code=404, detail=f"Test {test_id} not found")
    result = await run_single_test(test_id, tenant_id)
    return {"result": result.to_dict()}


@router.post("/run-all", summary="Run all atomic tests")
async def run_all(
    tenant_id: str = Depends(get_tenant_id),
    user: CurrentUser = Depends(require_testing_execute),
):
    results = await run_all_tests(tenant_id)
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    avg_time = 0.0
    if results:
        avg_time = sum(r.detection_time_ms for r in results) / len(results)
    return {
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "avg_detection_time_ms": round(avg_time, 2),
        },
        "results": [r.to_dict() for r in results],
    }


@router.get("/results", summary="List test run results")
async def list_results(
    user: CurrentUser = Depends(require_testing_view),
):
    results = await run_all_tests()
    return {"results": [r.to_dict() for r in results]}


@router.post("/sigma/validate", summary="Validate a Sigma YAML rule")
async def validate_sigma(
    request: SigmaValidateRequest,
    user: CurrentUser = Depends(require_testing_execute),
):
    result = validate_sigma_yaml(request.yaml_content)
    return SigmaValidateResponse(
        valid=result.valid,
        rule_name=result.rule_name,
        severity=result.severity,
        risk_score=result.risk_score,
        errors=[e.to_dict() for e in result.errors],
        warnings=[w.to_dict() for w in result.warnings],
    )
