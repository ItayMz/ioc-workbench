import re

from app.regex.patterns import REFANG_PATTERNS


def refang(value: str) -> str:
    """
    Convert common defanged IOC formats back to usable indicators.

    Examples:
    hxxps://evil[.]com/login -> https://evil.com/login
    hxxp[://]www[.]google[.]com -> http://www.google.com
    1[.]2[.]3[.]4 -> 1.2.3.4
    test[@]example[.]com -> test@example.com
    """
    cleaned = value.strip().strip('"').strip("'")

    for old, new in REFANG_PATTERNS.items():
        cleaned = cleaned.replace(old, new)

    cleaned = cleaned.replace("\\.", ".")

    cleaned = re.sub(r"\s+", "", cleaned)

    return cleaned