from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime

from backend.services.email_service import (
    analyze_sender,
    analyze_subject,
    analyze_body,
    compute_email_threat_score,
)
from backend.services.model_service import predict
from backend.services.virustotal_service import scan as vt_scan
from backend.services.google_sb_service import check as gsb_check
from backend.utils.email_utils import extract_urls
from backend.utils.fusion import combine
from backend.routes.history import save_scan

router = APIRouter()


class EmailScanRequest(BaseModel):
    sender: str
    subject: str
    body: str


class URLScanResult(BaseModel):
    url: str
    verdict: str
    confidence: float
    threat_score: int
    ai_result: Dict
    vt_result: Dict
    gsb_result: Dict
    fusion_explanation: str


class EmailScanResponse(BaseModel):
    verdict: str
    overall_score: int
    sender_analysis: Dict
    subject_analysis: Dict
    body_analysis: Dict
    url_results: List[URLScanResult]
    explanation: str
    timestamp: str


@router.post("/scan/email", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest):
    try:
        sender_analysis = analyze_sender(request.sender)
        subject_analysis = analyze_subject(request.subject)
        body_analysis = analyze_body(request.body)

        # Extract and scan URLs from the body
        urls = extract_urls(request.body)
        url_results = []

        for url in urls[:10]:
            # Run scans for each URL
            ai_result = predict(url)
            vt_result = await vt_scan(url)
            gsb_result = await gsb_check(url)
            fused = combine(ai_result, vt_result, gsb_result)

            url_results.append(
                URLScanResult(
                    url=url,
                    verdict=fused["verdict"],
                    confidence=fused["confidence"],
                    threat_score=fused["threat_score"],
                    ai_result=ai_result,
                    vt_result=vt_result,
                    gsb_result=gsb_result,
                    fusion_explanation=fused["explanation"],
                )
            )

        # Compute overall email threat score
        email_score = compute_email_threat_score(
            sender_analysis, subject_analysis, body_analysis, [r.dict() for r in url_results]
        )

        response = EmailScanResponse(
            verdict=email_score["verdict"],
            overall_score=email_score["overall_score"],
            sender_analysis=sender_analysis,
            subject_analysis=subject_analysis,
            body_analysis=body_analysis,
            url_results=url_results,
            explanation=email_score["explanation"],
            timestamp=datetime.utcnow().isoformat(),
        )

        save_scan({**response.dict(), "scan_type": "email"})

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
