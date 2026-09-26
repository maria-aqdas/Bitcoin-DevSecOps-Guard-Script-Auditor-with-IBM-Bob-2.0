# 🛡️ Bitcoin DevSecOps Guard & Script Auditor with IBM Bob 2.0

An AI-accelerated security auditor and test suite generator for Bitcoin backend scripts, built using **Python FastAPI** and powered by **IBM Bob 2.0**.

## 🚀 Key Features
- **Bitcoin Script & Transaction Auditor:** Detects dangerous patterns like exposed private keys, arbitrary execution calls (`exec`), and dust limit violations.
- **Address & Protocol Verification:** Validates Testnet and Mainnet SegWit/P2WPKH and P2TR addresses.
- **Autonomous Test Suite by IBM Bob 2.0:** Bob generated an exhaustive automated test suite (`test_auditor.py`) covering edge cases and regressions.

## 🤖 IBM Bob 2.0 Integration & Evidence
- **Agent Mode Planning & Execution:** Bob 2.0 analyzed the backend architecture and planned the unit testing structure.
- **Comprehensive Test Results:** 88 comprehensive test cases executed and passed in **0.83s**.

### Task Session Screenshots
- **Bob Agent Mode Task Completion:** `screenshots/02_bob_tasks_completed.png`
- **88 Tests Passed Verification:** `screenshots/03_pytest_88_passed.png`
- **Interactive Security Dashboard:** `screenshots/04_working_dashboard.png`

## 🛠️ How to Run Locally
1. Clone the repository:
   ```bash
   git clone <YOUR_REPO_URL>
   cd bitcoin-ai-auditor
