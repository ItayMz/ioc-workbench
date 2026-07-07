from pydantic import BaseModel, ConfigDict

from app.enums.indicator_type import IndicatorType


class ParsedIOC(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    original_value: str
    refanged_value: str
    indicator_type: IndicatorType | None = None
    valid: bool = False
    reason: str | None = None