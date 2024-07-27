class RiskCalculator:
    def __init__(self):
        self.vuln_score = 0
        self.bi_score = 0
        self.risk_score = 0

    def calculate_vuln_score(self, input_data, config):
        scores = [
            (config['Associated Threat Intelligence'][input_data.Associated_Threat_Intelligence], config['Associated Threat Intelligence']['Overall']),
            (config['Exploitability Code Maturity'][input_data.Exploitability_Code_Maturity], config['Exploitability Code Maturity']['Overall']),
            (input_data.CVSS_Base_Score, config['CVSS Base Score']['Overall']),
            (config['Attack Vector'][input_data.Attack_Vector], config['Attack Vector']['Overall']),
            (config['User Interaction'][input_data.User_Interaction], config['User Interaction']['Overall']),
            (config['Privileges Required'][input_data.Privileges_Required], config['Privileges Required']['Overall']),
            (config['Remediation Level'][input_data.Remediation_Level], config['Remediation Level']['Overall'])
        ]
        return sum(score * overall for score, overall in scores)

    def calculate_business_impact_score(self, input_data, config):
        scores = [
            (config['Connectivity'][input_data.Connectivity], config['Connectivity']['Overall']),
            (config['Asset Significance'][input_data.Asset_Significance], config['Asset Significance']['Overall']),
            (config['Exposure Prevalence'][input_data.Exposure_Prevalence], config['Exposure Prevalence']['Overall']),
            (config['Business Impact'][input_data.Business_Impact], config['Business Impact']['Overall'])
        ]
        return sum(score * overall for score, overall in scores)

    def calculate_risk_score(self):
        return self.vuln_score + self.bi_score

    def calculate(self, input_data, config):
        self.vuln_score = self.calculate_vuln_score(input_data, config)
        self.bi_score = self.calculate_business_impact_score(input_data, config)
        self.risk_score = self.vuln_score + self.bi_score
        return {"Vulnerability Score": self.vuln_score, "Business Impact Score": self.bi_score, "Risk Score": self.risk_score}
