from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.enums.indicator_type import IndicatorType
from app.models.campaign import Campaign, CampaignStatistics
from app.models.ioc import ParsedIOC


def test_campaign_model_supports_nested_indicators_and_statistics():
    indicator = ParsedIOC(
        original_value="https://example.com",
        refanged_value="https://example.com",
        indicator_type=IndicatorType.URL,
        valid=True,
    )
    campaign = Campaign(
        campaign_name="Lumma Stealer",
        source_email_text="hello from an email",
        title="Block Lumma Stealer Indicators",
        description="Indicators associated with the Lumma Stealer campaign.",
        recommended_actions="Block the listed indicators and investigate any historical communication.",
        indicators=[indicator],
        statistics=CampaignStatistics(total_count=1, valid_count=1, invalid_count=0, counts_by_type={"Url": 1}),
    )

    assert campaign.campaign_name == "Lumma Stealer"
    assert campaign.source_email_text == "hello from an email"
    assert campaign.indicators[0].indicator_type is IndicatorType.URL
    assert campaign.statistics.total_count == 1
    assert campaign.statistics.counts_by_type == {"Url": 1}
