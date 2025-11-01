# SSLMon Project Status
**Last Updated:** 2025-11-01 00:01 UTC  
**Author:** Doug Hesseltine

## Current Status

### Completed Features
1. **SMTP Configuration with Password Preservation**
   - Fixed bug where blank password field would revert other SMTP settings
   - Password is now preserved when left blank, while other fields update correctly
   - Committed and deployed successfully

2. **Certificate Paste/Upload Feature**
   - Added new tab on domains page to paste PEM-formatted certificates
   - Backend route parses certificate and extracts expiry/issuer information
   - Certificates can be added to monitoring without needing live SSL connection

3. **CA Renewal Link Improvements**
   - Enhanced CA detection logic for Let's Encrypt variants (WE1, R3, R4, R10, R11, E1-E9)
   - Fixed missing renewal buttons for certain CA issuers
   - Properly handles Let's Encrypt short codes while avoiding false positives

4. **SMTP Alert Testing**
   - Added "Test Warning Alert" and "Test Critical Alert" buttons to SMTP config page
   - Allows manual testing of email alerts without waiting for certificate expiry
   - Uses fake domain names and expiry dates for testing

5. **Alert Thresholds UI Enhancement**
   - Made alert threshold settings more visible in blue info box on SMTP config page
   - Clearer presentation of warning (30 days) and critical (14 days) thresholds

6. **Network Discovery Feature** (PARTIAL - see issues below)
   - Three scanning modes implemented:
     - Auto-detect local networks
     - Manual IP range scan (CIDR or range notation)
     - DNS zone query for Windows domain integration
   - Backend scanning logic implemented in `network_scanner.py`
   - Discovered hosts can be selected and added to monitoring
   - Link added to domains page

## Current Issues

### Critical Issue: SSE Progress Bar Crash
**Problem:** Network discovery scan page crashes/dies when running scans

**Technical Details:**
- Implemented Server-Sent Events (SSE) for real-time progress bar updates
- Initial implementation used Flask session storage - doesn't work with SSE long-lived connections
- Switched to global `scan_state` dictionary with unique scan IDs
- Code is committed to GitHub (commits `70e9aeb` and `1a4d9c2`)
- **Server deployment status unknown** - git repository not found at `/opt/sslmon/` on server

**What Was Attempted:**
1. Added SSE endpoint `/network-discovery/scan-progress/<scan_id>`
2. Created global `scan_state = {}` dictionary in app.py
3. Each scan gets unique ID via `secrets.token_hex(8)`
4. Progress updates stream via SSE with current/total/percent/discovered_count
5. Automatic cleanup after 5 minutes

**Files Modified:**
- `app.py` - Added global scan_state, modified all three scan routes, created SSE endpoint
- `templates/network_discovery.html` - Progress bar UI and SSE JavaScript client

### Deployment Issue
**Problem:** Unable to deploy latest code to production server

**Server Details:**
- IP: `10.250.0.158`
- User: `sslmon`
- Container: `sslmon` (not `sslmon-app-1`)
- Expected path: `/opt/sslmon/`

**Issue:** 
- Running `cd /opt/sslmon && git status` returns "fatal: not a git repository"
- Directory exists but appears to not be a git clone
- May have been deployed via direct file copy or different method

**Action Needed:**
- Determine actual deployment method on server
- Either:
  - Clone GitHub repo to `/opt/sslmon/` and redeploy, OR
  - Copy files directly and rebuild container

## Server Information
- **Host:** 10.250.0.158
- **User:** sslmon
- **Container Name:** sslmon
- **Docker Image:** sslmon:3.9
- **Data Volume:** /opt/sslmon-data
- **GitHub Repo:** github.com:hesseltined/sslmon.git

## Next Steps

### Immediate (Fix SSE Crash)
1. SSH to server and investigate `/opt/sslmon/` directory structure
2. Determine how code was originally deployed
3. Deploy latest code with SSE fixes (commits 70e9aeb and 1a4d9c2)
4. Test network discovery scans with progress bar
5. Check docker logs for any Python errors during scan

### Short-term Enhancements
1. Add network scan history/logging
2. Implement concurrent scanning (thread pool) for faster scans
3. Add scan result export (CSV/JSON)
4. Allow saving scan presets (frequently used IP ranges)

### Long-term Features
1. Windows DNS zone integration refinement
2. Scheduled automatic network discovery scans
3. Certificate chain validation
4. Multi-domain certificate support
5. API endpoints for programmatic access

## Code Repository
- **GitHub:** github.com:hesseltined/sslmon.git
- **Branch:** main
- **Latest Commits:**
  - `1a4d9c2` - Fix SSE scan progress by using global scan_state instead of session
  - `70e9aeb` - Add real-time progress bar for network discovery scans using SSE
  - `cc3585b` - Add test alert buttons and improve threshold visibility

## Dependencies
- Python 3.9
- Flask
- netifaces (for network detection)
- dnspython (for DNS queries)
- cryptography (for certificate parsing)
- All deps managed in requirements.txt

## Notes
- All code follows Windows ASCII compatibility (no emoji in code/docs per project rules)
- Documentation HTML should be updated with version numbers and dates
- Custom SMTP config working correctly
- Certificate monitoring core functionality stable and working
