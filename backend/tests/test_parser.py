from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.enums.action import Action
from app.enums.category import Category
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


def test_hash_indicators_get_block_and_remediate_action():
    md5_ioc = parse_ioc("0123456789abcdef0123456789abcdef")
    sha1_ioc = parse_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    sha256_ioc = parse_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    assert md5_ioc.action is Action.BLOCK_AND_REMEDIATE
    assert sha1_ioc.action is Action.BLOCK_AND_REMEDIATE
    assert sha256_ioc.action is Action.BLOCK_AND_REMEDIATE


def test_non_hash_indicators_get_block_action_and_invalid_have_none():
    url_ioc = parse_ioc("https://example.com")
    ip_ioc = parse_ioc("8.8.8.8")
    domain_ioc = parse_ioc("example.com")
    email_ioc = parse_ioc("user@example.com")
    invalid_ioc = parse_ioc("not-an-ioc")

    assert url_ioc.action is Action.BLOCK
    assert ip_ioc.action is Action.BLOCK
    assert domain_ioc.action is Action.BLOCK
    assert email_ioc.action is Action.BLOCK
    assert invalid_ioc.action is None


def test_valid_indicators_get_malware_category_and_alerts():
    url_ioc = parse_ioc("https://example.com")
    hash_ioc = parse_ioc("0123456789abcdef0123456789abcdef")

    assert url_ioc.category is Category.MALWARE
    assert url_ioc.generate_alert is True
    assert hash_ioc.category is Category.MALWARE
    assert hash_ioc.generate_alert is True


def test_invalid_indicators_have_no_category_or_alerts():
    invalid_ioc = parse_ioc("not-an-ioc")

    assert invalid_ioc.category is None
    assert invalid_ioc.generate_alert is None
