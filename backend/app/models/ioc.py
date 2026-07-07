from pydantic import BaseModel, ConfigDict

from app.enums.action import Action
from app.enums.category import Category
from app.enums.indicator_type import IndicatorType


class ParsedIOC(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    original_value: str
    refanged_value: str
    indicator_type: IndicatorType | None = None
    action: Action | None = None
    category: Category | None = None
    generate_alert: bool | None = None
    severity: str | None = None
    expiration_time: str | None = None
    valid: bool = False
    reason: str | None = None