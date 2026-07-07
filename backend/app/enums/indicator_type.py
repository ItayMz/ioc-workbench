from enum import Enum


class IndicatorType(str, Enum):
    URL = "Url"
    DOMAIN_NAME = "DomainName"
    IP_ADDRESS = "IpAddress"
    FILE_MD5 = "FileMd5"
    FILE_SHA1 = "FileSha1"
    FILE_SHA256 = "FileSha256"
    SENDER_EMAIL_ADDRESS = "SenderEmailAddress"
