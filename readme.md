# PyDefender: Python Package Security Checker

A comprehensive security scanner for Python packages that combines multiple security tools into a single interface.

## Overview

This tool performs security checks on Python packages using four industry-standard security tools:

1. **Safety** - Checks dependencies against known vulnerabilities in the PyUp.io database
2. **pip-audit** - Audits Python packages using the Python Packaging Advisory Database (PyPA)  
3. **Bandit** - Static code analysis to find common security issues in Python code
4. **Semgrep** - Lightweight static analysis for identifying security patterns and vulnerabilities

The script can be used to scan either:
- An installed Python package (by name)
- A local directory containing Python code

## Features

- Comprehensive security scanning using multiple tools
- Automatic discovery of installed package locations
- Detailed reports with vulnerability information
- Support for including/excluding specific tools
- Automatic report generation with timestamps
- Windows compatibility (with automatic tool adjustments)

## Setup Instructions

### Prerequisites

- Python 3.6 or higher
- pip package manager

### Installation

1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/yourusername/PyDefender.git
   cd PyDefender
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   This will install all the security tools needed:
   - safety
   - pip-audit
   - bandit
   - semgrep

### Troubleshooting Installation

- If you encounter permission issues during installation, try using:
  ```bash
  pip install --user -r requirements.txt
  ```

- On Windows, Semgrep is not officially supported and will be automatically excluded

- Some tools may require additional system dependencies:
  - For Ubuntu/Debian: `apt-get install build-essential python3-dev`
  - For macOS: `xcode-select --install`

## Usage

### Basic Usage

Scan an installed package:
```bash
python PyDefender.py requests
```

Scan a local directory:
```bash
python PyDefender.py /path/to/your/project
```

### Advanced Usage

Include only specific tools:
```bash
python PyDefender.py requests --include safety pip-audit
```

Exclude specific tools:
```bash
python PyDefender.py requests --exclude semgrep
```

Don't save the report to a file:
```bash
python PyDefender.py requests --no-save
```

Set a global timeout for all tools:
```bash
python PyDefender.py requests --timeout 120
```

## Function Documentation

For detailed documentation of all functions, please see the [FUNCTIONS.md](FUNCTIONS.md) file.

## Code Examples

### Example 1: Checking a Common Package

```python
# Import the main function from the script
from PyDefender import check_package_security

# Check the 'requests' package
results, issues, missing_tools, excluded_tools, semgrep_excluded = check_package_security('requests')

# Print summary
print(f"Found {len(issues)} potential security issues")
```

### Example 2: Integrating into Your CI/CD Pipeline

```python
import sys
from security_checker import check_package_security

# Run security check on your package
_, issues, _, _, _ = check_package_security('./my_package')

# Count high severity issues
high_severity_count = sum(1 for issue in issues 
                          if issue.get('severity') == 'HIGH' or issue.get('severity') == 'CRITICAL')

# Fail the build if high severity issues are found
if high_severity_count > 0:
    print(f"SECURITY CHECK FAILED: Found {high_severity_count} high severity issues")
    sys.exit(1)
else:
    print("SECURITY CHECK PASSED")
    sys.exit(0)
```

### Example 3: Custom Report Format

```python
from security_checker import check_package_security
import json

# Run the security check
_, issues, _, _, _ = check_package_security('flask')

# Convert to JSON format
json_report = json.dumps({
    'package': 'flask',
    'scan_time': datetime.now().isoformat(),
    'issues': issues
}, indent=2)

# Save to file
with open('security_report.json', 'w') as f:
    f.write(json_report)
```

## Dependencies

The script relies on the following external tools:

| Tool | Purpose | Version |
|------|---------|---------|
| Safety | Checks dependencies against known vulnerabilities | ≥2.3.5 |
| pip-audit | Audits Python packages using PyPA database | ≥2.5.0 |
| Bandit | Static code analysis for security issues | ≥1.7.4 |
| Semgrep | Lightweight static analysis for security patterns | ≥1.29.0 |

### Additional Python Modules Used

- `os`, `sys`, `json`, `subprocess`, `tempfile`, `shutil`, `argparse`, `re`, `platform`
- `datetime` from `datetime`
- `defaultdict` from `collections`
- `lru_cache` from `functools`

## Configuration Guide

While the script doesn't require any configuration files, you can customize its behavior:

### Global Timeout Adjustment

You can set a global timeout for all security tools using the `--timeout` parameter.

### Customizing Tool Behavior

To modify the behavior of individual security tools:

- **Safety**: Create a `.safety-policy.yml` file in your project root
- **Bandit**: Create a `.bandit` configuration file
- **Semgrep**: Create a `.semgrep.yml` configuration file

### GitHub Integration

You can create a GitHub Action workflow:

```yaml
name: Security Check

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    - name: Run security check
      run: |
        python PyDefender.py .
```

## Version History

- **1.0.0** (2025-02-27): Initial release
  - Comprehensive scanning with Safety, pip-audit, Bandit and Semgrep
  - Support for package names and directory paths
  - Automatic report generation

## License

[MIT License](LICENSE)

## Acknowledgements

This tool combines several excellent open-source security tools:

- [Safety](https://github.com/pyupio/safety)
- [pip-audit](https://github.com/pypa/pip-audit)
- [Bandit](https://github.com/PyCQA/bandit)
- [Semgrep](https://github.com/returntocorp/semgrep)

## Future Improvements

- Add support for additional security tools
- Create a web-based report interface
- Add severity scoring system that normalizes across tools
- Implement CI/CD pipeline integrations
- Add support for Python package manifest scanning
