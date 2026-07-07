from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.enums.indicator_type import IndicatorType
from app.services.parser import parse_ioc


def test_parse_ioc_returns_enum_indicator_for_url():
    parsed = parse_ioc("https://example.com")

    assert parsed.indicator_type is IndicatorType.URL
    assert parsed.valid is True


def test_parse_ioc_returns_enum_indicator_for_ip_and_domain():
    ip_ioc = parse_ioc("8.8.8.8")
    domain_ioc = parse_ioc("example.com")

    assert ip_ioc.indicator_type is IndicatorType.IP_ADDRESS
    assert domain_ioc.indicator_type is IndicatorType.DOMAIN_NAME


def test_parse_ioc_returns_enum_indicator_for_email_and_hashes():
    email_ioc = parse_ioc("user@example.com")
    md5_ioc = parse_ioc("0123456789abcdef0123456789abcdef")
    sha1_ioc = parse_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    sha256_ioc = parse_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    assert email_ioc.indicator_type is IndicatorType.SENDER_EMAIL_ADDRESS
    assert md5_ioc.indicator_type is IndicatorType.FILE_MD5
    assert sha1_ioc.indicator_type is IndicatorType.FILE_SHA1
    assert sha256_ioc.indicator_type is IndicatorType.FILE_SHA256
