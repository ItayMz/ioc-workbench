import re
from ipaddress import ip_address

from app.enums.indicator_type import IndicatorType
from app.models.ioc import ParsedIOC
from app.services.refang import refang


def parse_ioc(value: str) -> ParsedIOC:
    cleaned_value = value.strip()
    refanged_value = refang(cleaned_value)

    if not cleaned_value:
        return ParsedIOC(
            original_value=value,
            refanged_value=refanged_value,
            valid=False,
            reason="empty_value",
        )

    if re.fullmatch(r"[0-9a-fA-F]{32}", refanged_value):
        indicator_type = IndicatorType.FILE_MD5
    elif re.fullmatch(r"[0-9a-fA-F]{40}", refanged_value):
        indicator_type = IndicatorType.FILE_SHA1
    elif re.fullmatch(r"[0-9a-fA-F]{64}", refanged_value):
        indicator_type = IndicatorType.FILE_SHA256
    else:
        try:
            ip_address(refanged_value)
            indicator_type = IndicatorType.IP_ADDRESS
        except ValueError:
            if re.fullmatch(r"https?://.+", refanged_value):
                indicator_type = IndicatorType.URL
            elif re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", refanged_value):
                indicator_type = IndicatorType.SENDER_EMAIL_ADDRESS
            elif re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", refanged_value):
                indicator_type = IndicatorType.DOMAIN_NAME
            else:
                indicator_type = None

    valid = indicator_type is not None
    reason = None if valid else "unsupported_indicator"

    return ParsedIOC(
        original_value=value,
        refanged_value=refanged_value,
        indicator_type=indicator_type,
        valid=valid,
        reason=reason,
    )
