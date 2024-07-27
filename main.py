from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN
from dotenv import load_dotenv
import os
from src.assessment import RiskCalculator
from src.constant import DEFAULT_CONFIG, VULN_CHECK_URL
from src.input import RiskInput
from src.cve_details import CVEDetails
import uvicorn

load_dotenv()
app = FastAPI()

# Define your API key and header name
API_KEY = os.getenv("API_KEY")  # Use environment variable
API_KEY_NAME = "access_token"

# Create an APIKeyHeader security scheme
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Dependency function to verify API key
async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key == API_KEY:
        return api_key
    else:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )

@app.get("/")
async def read_root(api_key: str = Depends(get_api_key)):
    return {"Welcome to Custom Risk Calculator"}

@app.get("/fetch/{cve}")
async def read_item(cve: str, api_key: str = Depends(get_api_key)):
    fetcher = CVEDetails
    data = fetcher.fetch_cve_data(cve)
    return data

@app.post("/calculate_risk")
async def calculate_risk(input: RiskInput, api_key: str = Depends(get_api_key)):
    risk_calculator = RiskCalculator()
    result = risk_calculator.calculate(input, DEFAULT_CONFIG)
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
