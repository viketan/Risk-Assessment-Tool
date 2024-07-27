from src.constant import VULN_CHECK_URL
import requests
from fastapi import HTTPException
import os

class CVEDetails():
    def __init__(self):...


    def fetch_cve_data(self, cve_id):
        url = VULN_CHECK_URL
        headers = {"accept": "application/json", "authorization": f"Bearer {os.getenv('VULNCHECK_API_KEY')}"}
        params = {'cve': cve_id}
        try:
            response = requests.get(url, params=params, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json().get('data', [])
            if not data:
                raise HTTPException(status_code=404, detail="CVE not found")
            metrics = data[0]['metrics']['cvssMetricV31'][0]['cvssData']
            formatted_data = {
                'base_score': metrics['baseScore'],
                'attackVector': metrics['attackVector'].lower(),
                'privilegesRequired': metrics['privilegesRequired'].lower(),
                'userInteraction': metrics['userInteraction'].lower()
            }
            return formatted_data
        except requests.RequestException as e:
            raise HTTPException(status_code=500, detail=f"Error fetching CVE data: {e}")