import sys, subprocess, json, os

REPO = "Mikeykorby/aegis-av"
TAG = "v2.2.1.5"
REL_NAME = "Aegis Security 2.2.1.5"
ASSET = r"C:\Users\ranchel\aegis-av\dist\aegis.exe"

# token from remote URL (never print it)
remote = subprocess.check_output(["git", "-C", r"C:\Users\ranchel\aegis-av", "remote", "get-url", "origin"]).decode().strip()
# https://USER:TOKEN@github.com/...
token = remote.split("@")[0].split("://", 1)[1].split(":", 1)[1]
api = "https://api.github.com/repos/%s/releases" % REPO
hdr = ["-H", "Accept: application/vnd.github+json",
       "-H", "Authorization: Bearer " + token,
       "-H", "X-GitHub-Api-Version: 2022-11-28"]

# 1) create release
body = json.dumps({
    "tag_name": TAG,
    "name": REL_NAME,
    "body": ("Aegis Security 2.2.1.5 — single-file Windows build.\n\n"
             "Portable `aegis.exe`: no installer, no dependencies (uses the system "
             "WebView2 runtime). Real-time shields, premium feature pages, system "
             "tray, and launch-at-startup.\n\n"
             "Changes in 2.2.1.4:\n"
             "- Kernel page: honest BCD/test-signing reporting — never claims "
             "'ready' when Secure Boot blocks Test Signing (firmware policy wall)\n"
             "- App-wide version alignment: self-version 2.2.1.4 + exe metadata "
             "2.2.1.4 (was drifted to 2.1.0 / 2.2.0.0)\n"
             "- App Updates is a dedicated sidebar page (no longer under Settings)\n"
             "- VPN nav removed (no free VPN bundled)\n"
             "- Footer is now a live protection/definitions status bar\n"
             "- Titlebar X minimizes to tray; window controls are real "
             "minimize/close\n"
             "- Honeytrap 'redeploy' actually arms (deploys) canary traps\n"
             "- Added visible JS error overlay for diagnosis\n\n"
             "Note: this is a user-mode security tool — it detects/quarantines and "
             "monitors; the kernel companion requires Secure Boot off or a "
             "WHQL-signed driver to load."),
    "draft": False,
    "prerelease": False,
})
print("Creating release...")
out = subprocess.run(["curl", "-sS", "-X", "POST", api] + hdr +
                     ["-H", "Content-Type: application/json", "--data-binary", "@-"],
                     input=body, capture_output=True, text=True)
print("HTTP rc:", out.returncode)
rel = json.loads(out.stdout)
print("release id:", rel.get("id"), "upload_url present:", "upload_url" in rel)
if "upload_url" not in rel:
    print("ERROR:", out.stdout[:500]); sys.exit(1)

# 2) upload asset
up = rel["upload_url"].split("{", 1)[0] + "?name=aegis.exe"
print("Uploading asset...")
upout = subprocess.run(["curl", "-sS", "-X", "POST", up] + hdr +
                       ["-H", "Content-Type: application/octet-stream",
                        "--data-binary", "@" + ASSET],
                       capture_output=True, text=True)
print("upload HTTP rc:", upout.returncode)
try:
    j = json.loads(upout.stdout)
    print("asset:", j.get("name"), j.get("size"), "browser_download_url:", j.get("browser_download_url"))
except Exception as e:
    print("upload response (non-json):", upout.stdout[:300])
print("DONE")
