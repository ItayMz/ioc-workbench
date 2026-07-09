from pathlib import Path
import csv
import io
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.routes.parse import IOCMetadata, ParseRequest, export_campaign_csv


def _read_csv_response(response):
    text = response.body.decode('utf-8-sig')
    return list(csv.reader(io.StringIO(text)))


def test_export_csv_endpoint_returns_expected_headers_and_file_response():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            campaignName='Storm-123',
            iocMetadata=[
                IOCMetadata(value='https://example.com', campaignName='Storm-123', category='CommandAndControl')
            ],
        )
    )

    rows = _read_csv_response(response)
    headers = rows[0]

    assert response.status_code == 200
    assert response.headers['content-type'].startswith('text/csv')
    assert response.headers['content-disposition'] == 'attachment; filename=defender_iocs.csv'
    assert headers == [
        'IndicatorType',
        'IndicatorValue',
        'ExpirationTime',
        'Action',
        'Severity',
        'Title',
        'Description',
        'RecommendedActions',
        'RbacGroups',
        'Category',
        'MitreTechniques',
        'GenerateAlert',
    ]


def test_export_csv_endpoint_uses_empty_expiration_and_recommended_actions():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            campaignName='Storm-123',
            iocMetadata=[
                IOCMetadata(value='https://example.com', campaignName='Storm-123', category='CommandAndControl')
            ],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[2] == ''
    assert row[7] == ''


def test_export_csv_endpoint_uses_row_level_campaign_and_category_metadata():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com evil.com',
            iocMetadata=[
                IOCMetadata(value='https://example.com', campaignName='Campaign One', category='C2'),
                IOCMetadata(value='evil.com', campaignName='Campaign Two', category='credential access'),
            ],
        )
    )

    rows = _read_csv_response(response)
    data_rows = rows[1:]

    by_value = {row[1]: row for row in data_rows}

    assert by_value['https://example.com'][5] == 'Campaign One IOC'
    assert by_value['https://example.com'][6] == 'Indicators associated with Campaign One.'
    assert by_value['https://example.com'][9] == 'CommandAndControl'

    assert by_value['evil.com'][5] == 'Campaign Two IOC'
    assert by_value['evil.com'][6] == 'Indicators associated with Campaign Two.'
    assert by_value['evil.com'][9] == 'CredentialAccess'


def test_export_csv_endpoint_uses_per_file_campaign_names_without_title_concatenation():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://first.example second.example',
            iocMetadata=[
                IOCMetadata(
                    value='https://first.example',
                    campaignName='Campaign A',
                    category='Execution',
                    sourceFile='file_a.csv',
                ),
                IOCMetadata(
                    value='second.example',
                    campaignName='Campaign B',
                    category='Discovery',
                    sourceFile='file_b.csv',
                ),
            ],
        )
    )

    rows = _read_csv_response(response)
    data_rows = rows[1:]
    by_value = {row[1]: row for row in data_rows}

    assert by_value['https://first.example'][5] == 'Campaign A IOC'
    assert by_value['https://first.example'][6] == 'Indicators associated with Campaign A.'
    assert by_value['second.example'][5] == 'Campaign B IOC'
    assert by_value['second.example'][6] == 'Indicators associated with Campaign B.'


def test_export_csv_endpoint_uses_manual_campaign_override_for_all_rows():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com evil.com',
            campaignName='Manual Campaign',
            iocMetadata=[
                IOCMetadata(value='https://example.com', campaignName='Campaign One', category='C2'),
                IOCMetadata(value='evil.com', campaignName='Campaign Two', category='CredentialAccess'),
            ],
        )
    )

    rows = _read_csv_response(response)
    data_rows = rows[1:]

    for row in data_rows:
        assert row[5] == 'Manual Campaign IOC'
        assert row[6] == 'Indicators associated with Manual Campaign.'


def test_export_csv_endpoint_falls_back_to_ioc_sweep_for_missing_campaign_name():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            iocMetadata=[IOCMetadata(value='https://example.com', category='UnknownCategory')],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[5] == 'General Threat Indicators'
    assert row[6] == 'Threat indicators manually submitted for blocking and investigation.'
    assert 'IOC Sweep' not in row[5]
    assert 'TSOC General IOC Collection' not in row[5]
    assert 'TSOC IOC Portal' not in row[6]
    assert row[9] == 'Malware'


def test_export_csv_endpoint_uses_csv_campaign_name_when_manual_name_missing():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            iocMetadata=[IOCMetadata(value='https://example.com', campaignName='CSV Campaign', category='Discovery')],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[5] == 'CSV Campaign IOC'
    assert row[6] == 'Indicators associated with CSV Campaign.'


def test_export_csv_endpoint_row_category_overrides_manual_default_category():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            defaultCategory='Ransomware',
            iocMetadata=[
                IOCMetadata(value='https://example.com', category='Discovery'),
            ],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[9] == 'Discovery'


def test_export_csv_endpoint_uses_manual_default_category_when_row_category_missing():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            defaultCategory='Ransomware',
            iocMetadata=[
                IOCMetadata(value='https://example.com', campaignName='Storm-1'),
            ],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[9] == 'Ransomware'


def test_export_csv_endpoint_invalid_manual_default_category_falls_back_to_malware():
    response = export_campaign_csv(
        ParseRequest(
            raw_text='https://example.com',
            defaultCategory='InvalidCategoryValue',
            iocMetadata=[IOCMetadata(value='https://example.com')],
        )
    )

    row = _read_csv_response(response)[1]
    assert row[9] == 'Malware'
