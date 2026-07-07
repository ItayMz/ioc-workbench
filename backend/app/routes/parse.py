from fastapi import APIRouter
from pydantic import BaseModel

from app.models.ioc import ParsedIOC
from app.services.parser import parse_bulk_text

router = APIRouter()


class ParseRequest(BaseModel):
    raw_text: str


class ParseResponse(BaseModel):
    indicators: list[ParsedIOC]
    total_count: int
    valid_count: int
    invalid_count: int


@router.post("/parse", response_model=ParseResponse)
def parse_bulk_iocs(payload: ParseRequest) -> ParseResponse:
    indicators = parse_bulk_text(payload.raw_text)
    valid_count = sum(1 for indicator in indicators if indicator.valid)

    return ParseResponse(
        indicators=indicators,
        total_count=len(indicators),
        valid_count=valid_count,
        invalid_count=len(indicators) - valid_count,
    )
