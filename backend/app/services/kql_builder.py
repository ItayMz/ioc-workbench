from ipaddress import ip_address

from app.enums.indicator_type import IndicatorType
from app.models.ioc import ParsedIOC
from app.services.refang import refang


VALID_LOOKBACK_DAYS = {7, 30, 90, 180, 365}
DEFAULT_LOOKBACK_DAYS = 90


def _escape_kql_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped


def _normalize_value(indicator: ParsedIOC) -> str | None:
    raw_value = indicator.refanged_value or indicator.original_value
    if not raw_value:
        return None

    cleaned = refang(raw_value).strip()
    if not cleaned:
        return None

    if indicator.indicator_type in {IndicatorType.FILE_MD5, IndicatorType.FILE_SHA1, IndicatorType.FILE_SHA256}:
        return cleaned.lower()

    if indicator.indicator_type is IndicatorType.DOMAIN_NAME:
        return cleaned.lower()

    if indicator.indicator_type is IndicatorType.IP_ADDRESS:
        try:
            return str(ip_address(refang(cleaned)))
        except ValueError:
            return None

    if indicator.indicator_type is IndicatorType.URL:
        return refang(cleaned)

    return refang(cleaned)


def _deduplicate(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _build_dynamic_list(values: list[str]) -> str:
    normalized_values = _deduplicate([value for value in values if value])
    if not normalized_values:
        return "dynamic([])"

    escaped_values = [f'"{_escape_kql_string(value)}"' for value in normalized_values]
    return "dynamic([" + ", ".join(escaped_values) + "])"


def _normalize_lookback_days(lookback_days: int | None) -> int:
    if lookback_days in VALID_LOOKBACK_DAYS:
        return lookback_days
    return DEFAULT_LOOKBACK_DAYS


def _build_query(template: str, variable_name: str, values: list[str], lookback_days: int) -> str | None:
    normalized_values = _deduplicate([value for value in values if value])
    if not normalized_values:
        return None

    dynamic_list = _build_dynamic_list(normalized_values)
    return template.format(variable_name=variable_name, dynamic_list=dynamic_list, lookback_days=lookback_days)


def build_kql_queries(grouped_iocs: dict[str, list[ParsedIOC]], lookback_days: int | None = None) -> dict[str, dict[str, object] | None]:
    resolved_lookback_days = _normalize_lookback_days(lookback_days)
    md5_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("md5", [])
        if indicator.indicator_type is IndicatorType.FILE_MD5
    ]
    sha1_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("sha1", [])
        if indicator.indicator_type is IndicatorType.FILE_SHA1
    ]
    sha256_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("sha256", [])
        if indicator.indicator_type is IndicatorType.FILE_SHA256
    ]
    ipv4_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("ipv4", [])
        if indicator.indicator_type is IndicatorType.IP_ADDRESS
    ]
    ipv6_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("ipv6", [])
        if indicator.indicator_type is IndicatorType.IP_ADDRESS
    ]
    domain_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("domains", [])
        if indicator.indicator_type is IndicatorType.DOMAIN_NAME
    ]
    url_values = [
        _normalize_value(indicator)
        for indicator in grouped_iocs.get("urls", [])
        if indicator.indicator_type is IndicatorType.URL
    ]

    queries = {
        "md5": {
            "query": _build_query(
                "let IOC_MD5 = {dynamic_list};\n"
                "DeviceFileEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where MD5 in~ (IOC_MD5)\n"
                "| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_MD5",
                md5_values,
                resolved_lookback_days,
            ),
            "count": len(md5_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceFileEvents"],
        },
        "sha1": {
            "query": _build_query(
                "let IOC_SHA1 = {dynamic_list};\n"
                "DeviceFileEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where SHA1 in~ (IOC_SHA1)\n"
                "| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_SHA1",
                sha1_values,
                resolved_lookback_days,
            ),
            "count": len(sha1_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceFileEvents"],
        },
        "sha256": {
            "query": _build_query(
                "let IOC_SHA256 = {dynamic_list};\n"
                "DeviceFileEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where SHA256 in~ (IOC_SHA256)\n"
                "| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, SHA1, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_SHA256",
                sha256_values,
                resolved_lookback_days,
            ),
            "count": len(sha256_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceFileEvents"],
        },
        "ipv4": {
            "query": _build_query(
                "let IOC_IPV4 = {dynamic_list};\n"
                "DeviceNetworkEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where RemoteIP in~ (IOC_IPV4) or LocalIP in~ (IOC_IPV4)\n"
                "| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_IPV4",
                ipv4_values,
                resolved_lookback_days,
            ),
            "count": len(ipv4_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceNetworkEvents"],
        },
        "ipv6": {
            "query": _build_query(
                "let IOC_IPV6 = {dynamic_list};\n"
                "DeviceNetworkEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where RemoteIP in~ (IOC_IPV6) or LocalIP in~ (IOC_IPV6)\n"
                "| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_IPV6",
                ipv6_values,
                resolved_lookback_days,
            ),
            "count": len(ipv6_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceNetworkEvents"],
        },
        "domains": {
            "query": _build_query(
                "let IOC_DOMAINS = {dynamic_list};\n"
                "union\n"
                "(DeviceNetworkEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where RemoteUrl has_any (IOC_DOMAINS)\n"
                "),\n"
                "(DeviceDnsEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where QueryName has_any (IOC_DOMAINS) or Name has_any (IOC_DOMAINS))\n"
                "| project Timestamp, DeviceName, ActionType, RemoteUrl, QueryName, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId",
                "IOC_DOMAINS",
                domain_values,
                resolved_lookback_days,
            ),
            "count": len(domain_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceNetworkEvents", "DeviceDnsEvents"],
        },
        "urls": {
            "query": _build_query(
                "let IOC_URLS = {dynamic_list};\n"
                "union\n"
                "(DeviceNetworkEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where RemoteUrl in~ (IOC_URLS)\n"
                "),\n"
                "(DeviceProcessEvents\n"
                "| where Timestamp >= ago({lookback_days}d)\n"
                "| where InitiatingProcessCommandLine has_any (IOC_URLS) or ProcessCommandLine has_any (IOC_URLS))\n"
                "| project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, ReportId",
                "IOC_URLS",
                url_values,
                resolved_lookback_days,
            ),
            "count": len(url_values),
            "lookbackDays": resolved_lookback_days,
            "tables": ["DeviceNetworkEvents", "DeviceProcessEvents"],
        },
    }

    return {key: value if value["query"] else None for key, value in queries.items()}
