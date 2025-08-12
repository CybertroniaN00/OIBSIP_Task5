# Nmap Scan Analysis Report for IP: 192.168.137.1
Target Summary
- IP Address Scanned: 192.168.137.1
- Host Status: Up (latency ~0.0003–0.0004s)
- Operating System: Microsoft Windows (exact version undetermined)
- Network Distance: 0 hops (likely local or directly connected)

## 1. nmap 192.168.137.1
Purpose:
Basic TCP port scan using default settings.
Results:
- Open Ports:
- 135/tcp → msrpc (Microsoft RPC)
- 139/tcp → netbios-ssn (NetBIOS Session Service)
- 445/tcp → microsoft-ds (Microsoft Directory Services)
Interpretation:
This scan reveals that the host is running Windows services commonly associated with file sharing and remote procedure calls. These ports are often used in SMB (Server Message Block) communication and can be potential vectors for vulnerabilities if not properly secured.

## 2. nmap -sV 192.168.137.1
Purpose:
Service version detection to identify software running on open ports.
Results:
- 135/tcp → Microsoft Windows RPC
- 139/tcp → Microsoft Windows netbios-ssn
- 445/tcp → microsoft-ds (version undetermined)
- Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Interpretation:
This scan confirms the services are Windows-native. The version detection helps in identifying potential vulnerabilities tied to specific service versions. However, port 445’s service version remains uncertain, which may require deeper probing or alternative tools.

## 3. nmap -A 192.168.137.1
Purpose:
Aggressive scan combining OS detection, version detection, script scanning, and traceroute.
Results:
- Open Ports & Services: Same as above
- OS Detection: No exact match; fingerprint suggests Windows
- Host Script Results:
- smb2-time: Shows system time
- smb2-security-mode: Message signing enabled but not required
Interpretation:
The aggressive scan provides deeper insights:
- OS fingerprinting failed to match exactly, likely due to firewall or custom configurations.
- SMB scripts reveal that SMBv2 is active and message signing is optional—this could be a security concern in untrusted networks.
- Clock skew is minimal, indicating time synchronization is functioning.

## 4. nmap -A 192.168.137.1 -oN C:\Users\ayu41\Desktop\Demo_scan_results.txt
Purpose:
Same aggressive scan as above, but with output saved to a file.
Results:
- Identical to previous -A scan
- Output saved to: Demo_scan_results.txt
Interpretation:
This step ensures scan results are archived for future reference or reporting. Useful for documentation, audit trails, or sharing with security teams.

# Nmap Scan Analysis Report for IP: 192.168.137.113
Target Summary
- IP Address Scanned: 192.168.137.113
- Host Status: Up (latency ~0.023–0.045s)
- MAC Address: D0:39:57:DC:7E:35 (Liteon Technology)
- Operating System: Microsoft Windows (likely Windows 11 or 10)
- Network Distance: 1 hop

## 1. nmap 192.168.137.113
Purpose:
Basic TCP port scan using default settings.
Results:
- Open Ports:
- 135/tcp → msrpc
- 139/tcp → netbios-ssn
- 445/tcp → microsoft-ds
- 2869/tcp → icslap (Internet Connection Sharing)
- 5500/tcp → hotline
Interpretation:
This scan reveals several open ports beyond the standard Windows SMB services. Port 2869 is associated with UPnP and ICS, which can expose internal services. Port 5500 is less common and may be hosting a custom or third-party application.

## 2. nmap -sV 192.168.137.113
Purpose:
Service version detection to identify software running on open ports.
Results:
- 135/tcp → Microsoft Windows RPC
- 139/tcp → Microsoft Windows netbios-ssn
- 445/tcp → microsoft-ds (version undetermined)
- 2869/tcp → Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
- 5500/tcp → hotline? (unrecognized service returning HTML content)
Interpretation:
The scan identifies a web service on port 2869 using Microsoft's HTTPAPI, typically linked to UPnP. Port 5500 returns a full HTML page titled "Portfolio", suggesting a personal or hosted web application. Nmap couldn't classify it, but the fingerprint indicates it's a custom HTTP server or web framework.

## 3. nmap -A 192.168.137.113
Purpose:
Aggressive scan combining OS detection, version detection, script scanning, and traceroute.
Results:
- Open Ports & Services: Same as above
- OS Detection:
- Likely Windows 11, 10, or Server editions (confidence ~90%)
- No exact match due to filtered ports
- Host Script Results:
- nbstat: NetBIOS name: TRING
- smb2-time: System time retrieved
- smb2-security-mode: Message signing enabled but not required
- clock-skew: 4 seconds
- Traceroute: 1 hop (local network)
## Interpretation:
The aggressive scan provides deeper insights:
- OS detection is fairly confident but not definitive due to limited port visibility.
- Port 5500 appears to host a custom portfolio website, returning HTML and CSS content.
- SMB message signing is optional, which may weaken security in untrusted environments.
- NetBIOS name "TRING" suggests a personalized or user-assigned device name.
