from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.enums.indicator_type import IndicatorType
from app.models.ioc import ParsedIOC
from app.services.kql_builder import build_kql_queries


def _ioc(value: str, indicator_type: IndicatorType) -> ParsedIOC:
    return ParsedIOC(
        original_value=value,
        refanged_value=value,
        indicator_type=indicator_type,
        valid=True,
    )


def test_md5_only_input_generates_only_md5_kql():
    queries = build_kql_queries({"md5": [_ioc("ABCDEF0123456789ABCDEF0123456789", IndicatorType.FILE_MD5)]})

    assert queries["md5"] is not None
    assert queries["sha1"] is None
    assert queries["sha256"] is None
    assert queries["ipv4"] is None
    assert queries["ipv6"] is None
    assert queries["domains"] is None
    assert queries["urls"] is None


def test_sha1_only_input_generates_only_sha1_kql():
    queries = build_kql_queries({"sha1": [_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IndicatorType.FILE_SHA1)]})

    assert queries["sha1"] is not None
    assert queries["md5"] is None
    assert queries["sha256"] is None


def test_sha256_only_input_generates_only_sha256_kql():
    queries = build_kql_queries({"sha256": [_ioc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", IndicatorType.FILE_SHA256)]})

    assert queries["sha256"] is not None
    assert queries["md5"] is None
    assert queries["sha1"] is None


def test_ipv4_only_input_generates_only_ipv4_kql():
    queries = build_kql_queries({"ipv4": [_ioc("8.8.8.8", IndicatorType.IP_ADDRESS)]})

    assert queries["ipv4"] is not None
    assert queries["ipv6"] is None
    assert queries["domains"] is None
    assert queries["urls"] is None


def test_ipv6_only_input_generates_only_ipv6_kql():
    queries = build_kql_queries({"ipv6": [_ioc("2001:db8::1", IndicatorType.IP_ADDRESS)]})

    assert queries["ipv6"] is not None
    assert queries["ipv4"] is None


def test_domain_only_input_generates_only_domains_kql():
    queries = build_kql_queries({"domains": [_ioc("Example.COM", IndicatorType.DOMAIN_NAME)]})

    assert queries["domains"] is not None
    assert queries["urls"] is None


def test_url_only_input_generates_only_urls_kql():
    queries = build_kql_queries({"urls": [_ioc("https://example.com/path?x=1", IndicatorType.URL)]})

    assert queries["urls"] is not None
    assert queries["domains"] is None


def test_mixed_ioc_input_generates_all_relevant_query_blocks():
    queries = build_kql_queries(
        {
            "md5": [_ioc("abc", IndicatorType.FILE_MD5)],
            "sha1": [_ioc("def", IndicatorType.FILE_SHA1)],
            "sha256": [_ioc("ghi", IndicatorType.FILE_SHA256)],
            "ipv4": [_ioc("8.8.8.8", IndicatorType.IP_ADDRESS)],
            "ipv6": [_ioc("2001:db8::1", IndicatorType.IP_ADDRESS)],
            "domains": [_ioc("example.com", IndicatorType.DOMAIN_NAME)],
            "urls": [_ioc("https://example.com", IndicatorType.URL)],
        }
    )

    assert queries["md5"] is not None
    assert queries["sha1"] is not None
    assert queries["sha256"] is not None
    assert queries["ipv4"] is not None
    assert queries["ipv6"] is not None
    assert queries["domains"] is not None
    assert queries["urls"] is not None


def test_empty_input_generates_no_query_blocks():
    queries = build_kql_queries({})

    assert queries["md5"] is None
    assert queries["sha1"] is None
    assert queries["sha256"] is None
    assert queries["ipv4"] is None
    assert queries["ipv6"] is None
    assert queries["domains"] is None
    assert queries["urls"] is None


def test_duplicate_iocs_are_removed():
    queries = build_kql_queries(
        {
            "md5": [
                _ioc("abc", IndicatorType.FILE_MD5),
                _ioc("abc", IndicatorType.FILE_MD5),
                _ioc("def", IndicatorType.FILE_MD5),
            ]
        }
    )

    assert '"abc"' in queries["md5"]["query"]
    assert '"def"' in queries["md5"]["query"]
    assert queries["md5"]["query"].count('"abc"') == 1


def test_defanged_iocs_are_refanged_before_kql_generation():
    queries = build_kql_queries({"domains": [_ioc("evil[.]com", IndicatorType.DOMAIN_NAME)]})

    assert "evil.com" in queries["domains"]["query"]
    assert "evil[.]com" not in queries["domains"]["query"]


def test_kql_escaping_works_for_quotes_and_backslashes():
    queries = build_kql_queries({"urls": [_ioc('https://example.com/a\\b"c', IndicatorType.URL)]})

    assert 'https://example.com/a\\\\b\\"c' in queries["urls"]["query"]


def test_default_lookback_uses_90_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]})

    assert "ago(90d)" in queries["md5"]["query"]


def test_custom_lookback_uses_7_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]}, lookback_days=7)

    assert "ago(7d)" in queries["md5"]["query"]


def test_custom_lookback_uses_30_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]}, lookback_days=30)

    assert "ago(30d)" in queries["md5"]["query"]


def test_custom_lookback_uses_180_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]}, lookback_days=180)

    assert "ago(180d)" in queries["md5"]["query"]


def test_custom_lookback_uses_365_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]}, lookback_days=365)

    assert "ago(365d)" in queries["md5"]["query"]


def test_invalid_lookback_falls_back_to_90_days():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]}, lookback_days=999)

    assert "ago(90d)" in queries["md5"]["query"]


def test_md5_query_returns_expected_table_metadata():
    queries = build_kql_queries({"md5": [_ioc("abc", IndicatorType.FILE_MD5)]})

    assert queries["md5"]["count"] == 1
    assert queries["md5"]["lookbackDays"] == 90
    assert queries["md5"]["tables"] == ["DeviceFileEvents"]


def test_sha1_query_returns_expected_table_metadata():
    queries = build_kql_queries({"sha1": [_ioc("abc", IndicatorType.FILE_SHA1)]})

    assert queries["sha1"]["count"] == 1
    assert queries["sha1"]["tables"] == ["DeviceFileEvents"]


def test_sha256_query_returns_expected_table_metadata():
    queries = build_kql_queries({"sha256": [_ioc("abc", IndicatorType.FILE_SHA256)]})

    assert queries["sha256"]["count"] == 1
    assert queries["sha256"]["tables"] == ["DeviceFileEvents"]


def test_ipv4_query_returns_expected_table_metadata():
    queries = build_kql_queries({"ipv4": [_ioc("8.8.8.8", IndicatorType.IP_ADDRESS)]})

    assert queries["ipv4"]["count"] == 1
    assert queries["ipv4"]["tables"] == ["DeviceNetworkEvents"]


def test_ipv6_query_returns_expected_table_metadata():
    queries = build_kql_queries({"ipv6": [_ioc("2001:db8::1", IndicatorType.IP_ADDRESS)]})

    assert queries["ipv6"]["count"] == 1
    assert queries["ipv6"]["tables"] == ["DeviceNetworkEvents"]


def test_domains_query_returns_expected_table_metadata():
    queries = build_kql_queries({"domains": [_ioc("example.com", IndicatorType.DOMAIN_NAME)]})

    assert queries["domains"]["count"] == 1
    assert queries["domains"]["tables"] == ["DeviceNetworkEvents", "DeviceDnsEvents"]


def test_urls_query_returns_expected_table_metadata():
    queries = build_kql_queries({"urls": [_ioc("https://example.com", IndicatorType.URL)]})

    assert queries["urls"]["count"] == 1
    assert queries["urls"]["tables"] == ["DeviceNetworkEvents", "DeviceProcessEvents"]
