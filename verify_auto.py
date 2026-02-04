import urllib.request
import urllib.parse
import json
import time
import subprocess
import sys
import os

# Start the Flask app in the background
# We assume the venv python is available or system python has flask. 
# Since app.py imports flask, pandas, plotly, we should try to use the same python that runs app.py
# Let's try to use the strict path to venv python if it exists, otherwise sys.executable
venv_python = os.path.join(os.getcwd(), "venv", "bin", "python")
if os.path.exists(venv_python):
    python_cmd = venv_python
else:
    python_cmd = sys.executable

# Make sure we can import flask check before starting?
# Actually, let's just try running it.
process = subprocess.Popen([python_cmd, "app.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(f"Starting Flask app using {python_cmd}...")
time.sleep(5) # Wait for it to start

def check_ioc(ioc_value):
    url = "http://127.0.0.1:5000/analyze"
    data = urllib.parse.urlencode({'ioc': ioc_value}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Request failed: {e}")
        return {}

def check_homepage():
    url = "http://127.0.0.1:5000/"
    try:
        with urllib.request.urlopen(url) as response:
            content = response.read().decode()
            if "Automated SOC Decision Workflows" in content and "background-color: var(--bg-color)" in content:
                print("✅ Homepage verified: Title and Theme CSS detected.")
                return True
            else:
                print("❌ Homepage verification failed: Missing title or theme CSS.")
                return False
    except Exception as e:
        print(f"❌ Homepage request failed: {e}")
        return False

try:
    # Test 0: Homepage & Theme
    print("\nTesting Homepage & Theme...")
    if not check_homepage():
        sys.exit(1)

    # Test 1: Known Bad IOC
    print("\nTesting Known Bad IOC (45.67.89.1)...")
    data = check_ioc("45.67.89.1")
    print(f"Status: {data.get('status')} | Decision: {data.get('decision')} | Risk: {data.get('risk_level')}")
    assert data.get('status') == "MALICIOUS"
    assert data.get('decision') == "Block"
    
    # Test 2: Simulated Random IP (Unknown)
    print("\nTesting Unknown IP (1.2.3.4) - Simulation...")
    data = check_ioc("1.2.3.4")
    print(f"Status: {data.get('status')} | Decision: {data.get('decision')} | Class: {data.get('classification')}")
    # We can't assert strict values due to randomness, but we check structure
    assert 'decision' in data
    assert 'factors' in data
    
    # Test 3: Clean IOC (non-IP string or simple text)
    print("\nTesting Clean Input (helloworld)...")
    data = check_ioc("helloworld")
    print(f"Status: {data.get('status')} | Decision: {data.get('decision')}")
    assert data.get('decision') == "Monitor"

    print("\n✅ Verification Passed!")

except Exception as e:
    print(f"\n❌ Verification Failed: {e}")
finally:
    process.terminate()
    print("Stopped Flask app.")
