DEFAULT_CONFIG = {
    'Associated Threat Intelligence': {
        'Overall': 0.10,
        'Phishing/Others': 4,
        'RCE/Priv Esc':	6,
        'Malware/DDoS':	8,
        'Ransomware/ZeroDay': 10
    },
    'Exploitability Code Maturity':{
        'Overall': 0.10,
        'Not Defined/Unproven':	3,
        'Proof-of-concept':	5,
        'Functional exploit code/Exploit code available': 8,
        'Actively Exploited':10
    },
    'CVSS Base Score': {
        'Overall':0.10,
        'Critical':9.0 - 10.0,
        'High':	7.0 - 8.9,
        'Medium':	4.0 - 6.9,
        'Low':	0-3.9
    },
    'Attack Vector':{
        'Overall': 0.5,
        'Physical': 4,
        'Local': 6,
        'Adjacent Network': 8,
        'Network': 10
    },
    'User Interaction':{
        'Overall': 0.10,
        'Required': 5,
        'None': 10
    },
    'Privileges Required':{
        'Overall': 0.10,
        'High': 2,
        'Low': 6,
        'None':10
    },
    'Remediation Level':{
        'Overall': 0.10,
        'Official Fix': 3,
        'Temporary Fix':5,
        'Workaround':7,
        'Unavailable':10
    },
    'Connectivity':{
        'Overall': 0.07,
        'Cloud': 4,                                                             
        'External Perimeter/Internally Hosted': 7,
        'Internet Facing/Externally Hosted': 10
    },
    'Asset Significance': {
        'Overall': 0.10,
        'Enduser Systems': 4,
        'On-Prem/ Cloud Servers': 6,
        'Networking/OT Device': 8,
        'Business Application Systems/Crown Jewels/3rd Party Hosted Application':10
    },
    'Exposure Prevalence':{
        'Overall': 0.08,
        'Few':	4,
        'Many':	6,
        'Majority':	8,
        'Widespread': 10
    },
    'Business Impact':{
        'Overall': 0.10,
        'Minimal': 4,
        'Major': 6,
        'Essential': 8,
        'Critical': 10
    }
}

VULN_CHECK_URL = "https://api.vulncheck.com/v3/index/nist-nvd2"