from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.regex.patterns import REFANG_PATTERNS
from app.services.refang import refang


def test_refang_patterns_constant_exists():
    assert isinstance(REFANG_PATTERNS, dict)
    assert "hxxps[://]" in REFANG_PATTERNS


def test_refang_converts_hxxps_scheme():
    assert refang("hxxps://evil[.]com/login") == "https://evil.com/login"


def test_refang_converts_hxxp_bracketed_scheme():
    assert refang("hxxp[://]www[.]google[.]com") == "http://www.google.com"


def test_refang_converts_bracketed_dots():
    assert refang("example[.]com") == "example.com"


def test_refang_converts_ip_defanging():
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"


def test_refang_converts_email_defanging():
    assert refang("test[@]example[.]com") == "test@example.com"


def test_refang_converts_escaped_dots():
    assert refang(r"example\.com") == "example.com"
