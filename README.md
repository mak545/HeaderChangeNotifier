Monitor and detect changes in HTTP response headers during web security testing directly inside Burp Suite.

# Header Change Notifier - Burp Suite Extension

A professional Burp Suite extension that detects and alerts when HTTP response headers change between requests to the same URL. Perfect for security researchers, penetration testers, and bug bounty hunters who need to monitor header changes that could indicate security misconfigurations.

## Features

- **Real-time Header Monitoring**: Automatically detects changes in HTTP response headers
- **Security-Focused**: Pre-configured to track critical security headers
- **Risk Assessment**: Automatically categorizes changes by risk level (Critical/High/Medium/Low)  
- **Professional UI**: Clean, table-based interface integrated into Burp Suite
- **Customizable Tracking**: Add/remove headers to monitor based on your needs
- **Export Functionality**: Export detected changes to CSV for reporting
- **Burp Suite Integration**: Creates alerts in Burp's issue tracker for high-risk changes
- **Performance Optimized**: Efficient memory usage and fast processing

## Tracked Headers (Default)
The extension comes pre-configured to monitor these security-critical headers:

| Header | Description | Risk Assessment |
|--------|-------------|-----------------|
| `Set-Cookie` | Session cookies and security attributes | High |
| `Content-Security-Policy` | CSP rules and restrictions | High |
| `X-Frame-Options` | Clickjacking protection | Medium |
| `X-Content-Type-Options` | MIME sniffing protection | Medium |
| `Referrer-Policy` | Referrer information control | Medium |
| `Strict-Transport-Security` | HTTPS enforcement | High |
| `X-XSS-Protection` | XSS filtering settings | Medium |
| `Access-Control-Allow-Origin` | CORS origin permissions | Medium |
| `Server` | Web server identification | Low |
| `X-Powered-By` | Technology stack disclosure | Low |

## Use Cases

- **Security Testing**: Monitor for security header changes during penetration testing
- **Bug Bounty Hunting**: Detect configuration changes that might introduce vulnerabilities
- **Development Testing**: Ensure security headers remain consistent across deployments
- **Compliance Monitoring**: Track security header compliance during assessments
- **Red Team Operations**: Identify infrastructure changes during long-term engagements

## Installation

### Method 1: Manual Installation

1. Download the `HeaderChangeNotifier.py` file from this repository
2. Open Burp Suite Professional or Community Edition
3. Go to `Extensions` → `Installed` → `Add`
4. Select `Python` as the extension type
5. Browse and select the `HeaderChangeNotifier.py` file
6. Click `Next` and verify the extension loads without errors
7. The extension will appear as a new tab called "Header Change Notifier"

### Method 2: BApp Store (Coming Soon)

The extension will be available through the official Burp Suite BApp Store once submitted and approved.

## Usage

### Basic Usage

1. **Start Monitoring**: Once installed, the extension automatically begins monitoring HTTP responses
2. **Browse Target**: Navigate through your target application normally
3. **Check Changes**: Visit the "Header Change Notifier" tab to see detected changes
4. **Review Alerts**: High-risk changes will also appear in Burp's main issue tracker

### Configuration

1. **Settings Tab**: Click the "Settings" tab within the extension
2. **Header Selection**: Check/uncheck headers you want to monitor
3. **Custom Headers**: Add custom headers using the input field
4. **Save Settings**: Click "Save Settings" to apply changes
### Exporting Results
1. Click the "Export CSV" button in the Header Changes tab
2. Choose your desired save location
3. The CSV will contain all detected changes with timestamps and risk levels


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact
Author: Mohamed  
Email: mohamed.cybersec@gmail.com

