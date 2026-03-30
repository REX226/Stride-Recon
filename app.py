import os
import subprocess
import concurrent.futures
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

RESULTS_DIR = "scan_results"
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

def run_cmd(cmd):
    """Executes a system command with a 60-second timeout."""
    try:
        process = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        output = process.stdout.strip()
        return output if output else "No results found."
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def full_pipeline():
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400

    report = {}
    subs_file = os.path.join(RESULTS_DIR, f"{target}_subs.txt")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # --- PHASE 1: DISCOVERY ---
        f_sub = executor.submit(run_cmd, f"subfinder -d {target} -silent")
        f_asset = executor.submit(run_cmd, f"assetfinder --subs-only {target}")
        f_gau = executor.submit(run_cmd, f"gau {target} --limit 30")
        
        # We must wait for subfinder to finish to create the file for dnsx/subjack
        sub_data = f_sub.result()
        with open(subs_file, "w") as f:
            f.write(sub_data if "Error" not in sub_data else target)

        # --- PHASE 2: VALIDATION & PROBING ---
        f_dns = executor.submit(run_cmd, f"dnsx -l {subs_file} -silent")
        f_http = executor.submit(run_cmd, f"httpx -l {subs_file} -silent -sc -title")
        f_port = executor.submit(run_cmd, f"naabu -host {target} -passive -silent")

        # --- PHASE 3: CRAWLING & VULNS ---
        # This uses 'known files' only, which is safe and fast
        f_kata = executor.submit(run_cmd, f"katana -u {target} -d 1 -kf all -silent -nc")
        f_nucl = executor.submit(run_cmd, f"nuclei -u {target} -passive -silent")
        f_arju = executor.submit(run_cmd, f"arjun -u https://{target} --stable -t 10")
        f_jack = executor.submit(run_cmd, f"subjack -w {subs_file} -timeout 20 -ssl")

        # --- MAPPING RESULTS (Variable Names must match exactly) ---
        report['subdomains'] = sub_data.split('\n')
        report['asset_discovery'] = f_asset.result().split('\n')
        report['archived_urls'] = f_gau.result().split('\n')
        report['dns_resolved'] = f_dns.result().split('\n') # Corrected Name
        report['web_probes'] = f_http.result().split('\n')
        report['passive_ports'] = f_port.result().split('\n')
        report['passive_endpoints'] = f_kata.result().split('\n')
        report['vulnerabilities'] = f_nucl.result().split('\n')
        report['parameters'] = f_arju.result().split('\n')
        report['takeover_checks'] = f_jack.result().split('\n')

    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False, port=5000)