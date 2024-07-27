from pydantic import BaseModel

class RiskInput(BaseModel):
    Associated_Threat_Intelligence: str
    Exploitability_Code_Maturity: str
    CVSS_Base_Score: float
    Attack_Vector: str
    User_Interaction: str
    Privileges_Required: str
    Remediation_Level: str
    Connectivity: str
    Asset_Significance: str
    Exposure_Prevalence: str
    Business_Impact: str