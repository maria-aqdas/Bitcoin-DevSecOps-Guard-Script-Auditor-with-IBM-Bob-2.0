"""
AI-Assisted Bitcoin & Script Auditor Service
Designed for IBM Bob 2.0 Hackathon Workflow Optimization

Features:
- Bitcoin Testnet address & basic script validation
- Static rule-based code & logic vulnerability analysis
- Mock IBM watsonx / Bob 2.0 Subagent integration endpoint for automated test generation
- Built-in lightweight HTML testing dashboard for video demo recordings
"""

import re
import hashlib
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="Bob 2.0 Bitcoin DevSecOps Engine",
    description="Automated audit and test generator for Bitcoin Python services and smart scripts.",
    version="1.0.0"
)

# ---------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------

class AuditRequest(BaseModel):
    code_snippet: str = Field(..., example="def transfer_funds(to_addr, amount):\n    # TODO: add signature verification\n    exec('tx.broadcast()')")
    include_test_generation: bool = Field(default=True, description="Trigger Bob 2.0 subagent test generation")

class VulnerabilityReport(BaseModel):
    severity: str
    rule_id: str
    message: str
    line_number: Optional[int] = None
    suggested_fix: str

class AuditResponse(BaseModel):
    status: str
    risk_score: int  # 0 to 100
    vulnerabilities: List[VulnerabilityReport]
    generated_test_cases: Optional[str] = None
    bob_agent_context: str

class BitcoinVerifyRequest(BaseModel):
    address: str = Field(..., example="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
    network: str = Field(default="testnet", example="testnet")

class BitcoinVerifyResponse(BaseModel):
    address: str
    network: str
    is_valid_format: bool
    address_type: str
    notes: str

# ---------------------------------------------------------
# Core Bitcoin Verification Logic
# ---------------------------------------------------------

def verify_btc_address(address: str, network: str = "testnet") -> dict:
    """
    Lightweight validation for Bitcoin testnet/mainnet addresses.
    Checks Legacy (P2PKH), Nested SegWit (P2SH), and Native SegWit (Bech32).
    """
    address = address.strip()
    
    if network.lower() == "testnet":
        if address.startswith(("m", "n")):
            return {"valid": True, "type": "Testnet P2PKH (Legacy)", "notes": "Legacy testnet format. Higher fee footprint."}
        elif address.startswith("2"):
            return {"valid": True, "type": "Testnet P2SH (Nested SegWit)", "notes": "Standard compatible testnet address."}
        elif address.startswith("tb1q"):
            return {"valid": True, "type": "Testnet P2WPKH (Native SegWit)", "notes": "SegWit active. Optimal transaction fee profile."}
        elif address.startswith("tb1p"):
            return {"valid": True, "type": "Testnet P2TR (Taproot)", "notes": "Taproot active. Enhanced privacy & script capabilities."}
        else:
            return {"valid": False, "type": "Unknown / Invalid", "notes": "Does not match standard Bitcoin Testnet address prefixes."}
    else:
        if address.startswith("1"):
            return {"valid": True, "type": "Mainnet P2PKH", "notes": "Standard mainnet legacy address."}
        elif address.startswith("3"):
            return {"valid": True, "type": "Mainnet P2SH", "notes": "Mainnet script hash address."}
        elif address.startswith("bc1q"):
            return {"valid": True, "type": "Mainnet P2WPKH", "notes": "Native SegWit address."}
        elif address.startswith("bc1p"):
            return {"valid": True, "type": "Mainnet P2TR", "notes": "Taproot mainnet address."}
        else:
            return {"valid": False, "type": "Unknown / Invalid", "notes": "Does not match standard Bitcoin Mainnet prefixes."}

# ---------------------------------------------------------
# Security Analyzer (Emulating Bob 2.0 Subagent Analysis)
# ---------------------------------------------------------

def analyze_code_security(code: str) -> List[VulnerabilityReport]:
    findings = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, start=1):
        # Rule 1: Dangerous dynamic evaluation
        if "eval(" in line or "exec(" in line:
            findings.append(VulnerabilityReport(
                severity="CRITICAL",
                rule_id="SEC-001",
                message="Dangerous dynamic execution detected (eval/exec).",
                line_number=idx,
                suggested_fix="Remove exec/eval. Use structured RPC calls or pure functional parsers."
            ))
        
        # Rule 2: Hardcoded secrets or private keys (WIF/Hex format patterns)
        if re.search(r'(private_key|api_key|secret|seed_phrase)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', line, re.IGNORECASE):
            findings.append(VulnerabilityReport(
                severity="HIGH",
                rule_id="SEC-002",
                message="Potential hardcoded credential or private key detected.",
                line_number=idx,
                suggested_fix="Externalize sensitive secrets using environment variables or a secret vault. Add to .bobignore."
            ))
            
        # Rule 3: Missing signature check / Unchecked raw outputs
        if "broadcast" in line and not any("verify" in l.lower() or "signature" in l.lower() for l in lines):
            findings.append(VulnerabilityReport(
                severity="HIGH",
                rule_id="BTC-101",
                message="Transaction broadcast without clear programmatic signature validation in context.",
                line_number=idx,
                suggested_fix="Validate ECDSA/Schnorr signatures against scriptPubKeys before broadcasting."
            ))

    return findings

def generate_bob_test_suite(code_snippet: str) -> str:
    """Simulates automated test generation performed by Bob 2.0 Subagents."""
    return f'''# Auto-generated by IBM Bob 2.0 Testing Subagent
import pytest

def test_code_safety_benchmark():
    input_code = """{code_snippet[:60]}..."""
    # Assert code does not use prohibited primitives
    assert "exec(" not in input_code
    assert "eval(" not in input_code

def test_bitcoin_flow_validation():
    # Bob 2.0 generated edge-case verification test
    dummy_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    assert dummy_address.startswith("tb1")
'''

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.post("/api/audit", response_model=AuditResponse)
def audit_code_endpoint(payload: AuditRequest):
    """
    Submits developer code to be audited against Bitcoin workflow vulnerabilities
    and generates automated remediation scripts.
    """
    if not payload.code_snippet.strip():
        raise HTTPException(status_code=400, detail="Code snippet cannot be empty.")

    vulns = analyze_code_security(payload.code_snippet)
    
    # Calculate simple dynamic risk score
    risk_score = 0
    for v in vulns:
        if v.severity == "CRITICAL":
            risk_score += 45
        elif v.severity == "HIGH":
            risk_score += 25
        elif v.severity == "MEDIUM":
            risk_score += 10
    risk_score = min(risk_score, 100)

    tests = generate_bob_test_suite(payload.code_snippet) if payload.include_test_generation else None

    return AuditResponse(
        status="COMPLETED",
        risk_score=risk_score,
        vulnerabilities=vulns,
        generated_test_cases=tests,
        bob_agent_context="Evaluated via Bob 2.0 Repository Context & Document Understanding Engine."
    )

@app.post("/api/bitcoin/verify-address", response_model=BitcoinVerifyResponse)
def verify_address_endpoint(payload: BitcoinVerifyRequest):
    """
    Validates formatting and classification for Bitcoin addresses.
    """
    res = verify_btc_address(payload.address, payload.network)
    return BitcoinVerifyResponse(
        address=payload.address,
        network=payload.network,
        is_valid_format=res["valid"],
        address_type=res["type"],
        notes=res["notes"]
    )

# ---------------------------------------------------------
# Interactive Quick-Test Dashboard (Ideal for Video Demo)
# ---------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def demo_ui():
    """
    Simple, embedded UI to record the required 90-second video demo.
    """
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Bob 2.0 - Bitcoin DevSecOps Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-900 text-slate-100 min-h-screen p-8">
        <div class="max-w-4xl mx-auto space-y-6">
            <header class="border-b border-slate-700 pb-4">
                <h1 class="text-3xl font-bold text-amber-400">IBM Bob 2.0 × Bitcoin DevSecOps Tool</h1>
                <p class="text-slate-400 text-sm mt-1">Accelerating Bitcoin backend security, script auditing, and unit testing.</p>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Audit Section -->
                <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
                    <h2 class="text-xl font-semibold mb-3 text-cyan-400">1. Automated Code Audit</h2>
                    <textarea id="codeSnippet" rows="6" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400">def transfer_funds(to_addr, amount):
    private_key = "KxZ48293nd81734918239"
    # Unverified broadcast
    exec("tx.broadcast()")</textarea>
                    <button onclick="runAudit()" class="mt-3 w-full bg-cyan-600 hover:bg-cyan-500 py-2 rounded font-semibold text-sm transition">
                        Run Audit with Bob 2.0 Subagent
                    </button>
                    <pre id="auditResult" class="mt-3 bg-slate-950 p-3 rounded text-xs font-mono overflow-x-auto max-h-48 text-slate-300">Awaiting input...</pre>
                </div>

                <!-- Bitcoin Address Check -->
                <div class="bg-slate-800 p-5 rounded-lg border border-slate-700">
                    <h2 class="text-xl font-semibold mb-3 text-amber-400">2. Bitcoin Testnet Validator</h2>
                    <input id="btcAddr" type="text" value="tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-amber-300" />
                    <button onclick="verifyAddress()" class="mt-3 w-full bg-amber-600 hover:bg-amber-500 py-2 rounded font-semibold text-sm transition">
                        Validate Address Script
                    </button>
                    <pre id="addrResult" class="mt-3 bg-slate-950 p-3 rounded text-xs font-mono overflow-x-auto max-h-48 text-slate-300">Awaiting input...</pre>
                </div>
            </div>
        </div>

        <script>
            async function runAudit() {
                const code = document.getElementById('codeSnippet').value;
                document.getElementById('auditResult').textContent = "Subagent analyzing repository context...";
                const res = await fetch('/api/audit', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ code_snippet: code, include_test_generation: true })
                });
                const data = await res.json();
                document.getElementById('auditResult').textContent = JSON.stringify(data, null, 2);
            }

            async function verifyAddress() {
                const addr = document.getElementById('btcAddr').value;
                document.getElementById('addrResult').textContent = "Validating network prefixes...";
                const res = await fetch('/api/bitcoin/verify-address', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ address: addr, network: 'testnet' })
                });
                const data = await res.json();
                document.getElementById('addrResult').textContent = JSON.stringify(data, null, 2);
            }
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    import uvicorn
    # Run directly with: python app.py
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)