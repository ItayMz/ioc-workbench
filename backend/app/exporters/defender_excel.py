from io import BytesIO
from enum import Enum

from openpyxl import Workbook

from app.enums.indicator_type import IndicatorType
from app.models.campaign import Campaign

HEADERS = [
    "IndicatorType",
    "IndicatorValue",
    "ExpirationTime",
    "Action",
    "Severity",
    "Title",
    "Description",
    "RecommendedActions",
    "RbacGroups",
    "Category",
    "MitreTechniques",
    "GenerateAlert",
]


def _to_excel_value(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, Enum):
        return value.value
    return value


def export_campaign_to_excel_bytes(campaign: Campaign) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "Defender"
    worksheet.append(HEADERS)

    for indicator in campaign.indicators:
        if not indicator.valid:
            continue
        if indicator.indicator_type is IndicatorType.SENDER_EMAIL_ADDRESS:
            continue

        worksheet.append(
            [
                _to_excel_value(indicator.indicator_type),
                _to_excel_value(indicator.refanged_value),
                _to_excel_value(indicator.expiration_time),
                _to_excel_value(indicator.action),
                _to_excel_value(indicator.severity),
                _to_excel_value(campaign.title),
                _to_excel_value(campaign.description),
                _to_excel_value(campaign.recommended_actions),
                "",
                _to_excel_value(indicator.category),
                "",
                _to_excel_value(indicator.generate_alert),
            ]
        )

    buffer = BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
