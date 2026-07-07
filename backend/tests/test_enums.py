from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.enums.action import Action
from app.enums.category import Category
from app.enums.indicator_type import IndicatorType
from app.models.ioc import ParsedIOC


def test_enums_use_supported_microsoft_defender_values():
    assert IndicatorType.URL.value == "Url"
    assert IndicatorType.DOMAIN_NAME.value == "DomainName"
    assert IndicatorType.IP_ADDRESS.value == "IpAddress"
    assert IndicatorType.FILE_MD5.value == "FileMd5"
    assert IndicatorType.FILE_SHA1.value == "FileSha1"
    assert IndicatorType.FILE_SHA256.value == "FileSha256"
    assert IndicatorType.SENDER_EMAIL_ADDRESS.value == "SenderEmailAddress"
    assert Action.BLOCK.value == "Block"
    assert Action.BLOCK_AND_REMEDIATE.value == "BlockAndRemediate"
    assert Category.MALWARE.value == "Malware"


def test_parsed_ioc_accepts_enum_values():
    ioc = ParsedIOC(
        original_value="https://example.com",
        refanged_value="https://example.com",
        indicator_type=IndicatorType.URL,
    )

    assert ioc.indicator_type is IndicatorType.URL

    ioc_from_string = ParsedIOC(
        original_value="example.com",
        refanged_value="example.com",
        indicator_type="DomainName",
    )

    assert ioc_from_string.indicator_type is IndicatorType.DOMAIN_NAME
