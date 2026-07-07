from pydantic import BaseModel, ConfigDict, Field

from app.models.ioc import ParsedIOC


class CampaignStatistics(BaseModel):
    total_count: int = 0
    valid_count: int = 0
    invalid_count: int = 0
    counts_by_type: dict[str, int] = Field(default_factory=dict)


class Campaign(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    campaign_name: str | None = None
    source_email_text: str | None = None
    title: str = ""
    description: str = ""
    recommended_actions: str = ""
    indicators: list[ParsedIOC] = Field(default_factory=list)
    statistics: CampaignStatistics = Field(default_factory=CampaignStatistics)
