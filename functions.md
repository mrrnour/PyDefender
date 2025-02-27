# PyDefender Function Documentation

This document provides detailed documentation for all functions in the PyDefender package security checker.

## Main Functions

### `check_package_security(package_name_or_path, include_tools=None, exclude_tools=None)`

Main function to check package security using multiple security tools.

**Parameters:**
- `package_name_or_path` (str): Either a package name (e.g., 'requests') or a path to source code
- `include_tools` (list): List of tools to include (default: all)
- `exclude_tools` (list): List of tools to exclude (default: none)

**Returns:**
- `str`: Formatted table with security findings
- `list`: All issues found
- `list`: Missing tools
- `list`: Path-based tools that were excluded
- `bool`: Whether Semgrep was excluded due to Windows

**Example:**
```python
results_text, issues, missing_tools, excluded_tools, semgrep_excluded = check_package_security('requests')
print(results_text)
```

### `find_package_path(package_name)`

Attempts to find the installed path of a Python package.

**Parameters:**
- `package_name` (str): Name of the package to locate

**Returns:**
- `str` or `None`: Path to the package if found, None otherwise

**Example:**
```python
path = find_package_path('requests')
if path:
    print(f"Package found at: {path}")
else:
    print("Package not found")
```

### `get_tool_version(tool_name)`

Gets the version of a security tool.

**Parameters:**
- `tool_name` (str): Name of the tool (safety, pip-audit, bandit, or semgrep)

**Returns:**
- `str`: Version of the tool, "Unknown", or "Not installed"

**Notes:**
- Uses `lru_cache` for caching results to avoid repeated subprocess calls
- Maximum cache size is 32 items

**Example:**
```python
version = get_tool_version('bandit')
print(f"Bandit version: {version}")
```

## Tool-Specific Functions

### `run_safety(package_name)`

Run safety check on the package.

**Parameters:**
- `package_name` (str): Name of the package to check

**Returns:**
- `dict`: Results from Safety containing vulnerabilities or error information

**Notes:**
- Uses a temporary file to create a requirements-like file for Safety
- Handles authentication errors with the Safety API
- Includes a 60-second timeout to prevent hanging

**Example:**
```python
safety_results = run_safety('django')
if 'error' in safety_results:
    print(f"Error: {safety_results['error']}")
else:
    print(f"Found {len(safety_results.get('vulnerabilities', []))} vulnerabilities")
```

### `run_pip_audit(package_name)`

Run pip-audit on the package.

**Parameters:**
- `package_name` (str): Name of the package to check

**Returns:**
- `dict`: Results from pip-audit containing vulnerabilities or error information

**Notes:**
- Uses a temporary file to create a requirements-like file for pip-audit
- Outputs in JSON format for easier parsing
- Includes a 60-second timeout to prevent hanging

**Example:**
```python
pip_audit_results = run_pip_audit('flask')
if 'error' in pip_audit_results:
    print(f"Error: {pip_audit_results['error']}")
else:
    vulns = pip_audit_results.get('vulnerabilities', [])
    print(f"Found {len(vulns)} vulnerabilities with pip-audit")
```

### `run_bandit(package_path)`

Run bandit on the package source code.

**Parameters:**
- `package_path` (str): Path to the package source code

**Returns:**
- `dict`: Results from Bandit containing vulnerabilities or error information

**Notes:**
- If package_path doesn't exist, attempts to find the installed package path
- Uses recursive analysis (-r flag) to check all Python files
- Outputs in JSON format for easier parsing
- Includes a 180-second timeout for larger packages

**Example:**
```python
bandit_results = run_bandit('/path/to/my_project')
if 'error' in bandit_results:
    print(f"Error: {bandit_results['error']}")
else:
    issues = bandit_results.get('results', [])
    print(f"Found {len(issues)} security issues with Bandit")
```

### `run_semgrep(package_path)`

Run semgrep on the package source code for security checks.

**Parameters:**
- `package_path` (str): Path to the package source code

**Returns:**
- `dict`: Results from Semgrep containing vulnerabilities or error information

**Notes:**
- Automatically skips if running on Windows as Semgrep is not officially supported
- If package_path doesn't exist, attempts to find the installed package path
- Uses the p/security-audit ruleset for comprehensive security checks
- Outputs in JSON format for easier parsing
- Includes a 300-second timeout for larger packages

**Example:**
```python
semgrep_results = run_semgrep('/path/to/my_project')
if 'skipped_due_to_platform' in semgrep_results and semgrep_results['skipped_due_to_platform']:
    print("Semgrep was skipped because it's not supported on this platform")
elif 'error' in semgrep_results:
    print(f"Error: {semgrep_results['error']}")
else:
    findings = semgrep_results.get('results', [])
    print(f"Found {len(findings)} security issues with Semgrep")
```

## Result Parsing Functions

### `parse_safety_results(safety_results, tool_version)`

Parse Safety results into a list of issues.

**Parameters:**
- `safety_results` (dict): Results returned from Safety
- `tool_version` (str): Version of Safety used

**Returns:**
- `list`: List of standardized issue dictionaries

**Example:**
```python
safety_results = run_safety('django')
issues = parse_safety_results(safety_results, get_tool_version('safety'))
for issue in issues:
    print(f"{issue['package']}: {issue['vulnerability']} ({issue['severity']})")
```

### `parse_pip_audit_results(pip_audit_results, tool_version)`

Parse pip-audit results into a list of issues.

**Parameters:**
- `pip_audit_results` (dict): Results returned from pip-audit
- `tool_version` (str): Version of pip-audit used

**Returns:**
- `list`: List of standardized issue dictionaries

**Example:**
```python
pip_audit_results = run_pip_audit('flask')
issues = parse_pip_audit_results(pip_audit_results, get_tool_version('pip-audit'))
for issue in issues:
    print(f"{issue['package']}: {issue['vulnerability']} ({issue['severity']})")
```

### `parse_bandit_results(bandit_results, tool_version)`

Parse Bandit results into a list of issues.

**Parameters:**
- `bandit_results` (dict): Results returned from Bandit
- `tool_version` (str): Version of Bandit used

**Returns:**
- `list`: List of standardized issue dictionaries

**Example:**
```python
bandit_results = run_bandit('/path/to/my_project')
issues = parse_bandit_results(bandit_results, get_tool_version('bandit'))
for issue in issues:
    print(f"{issue['package']}: {issue['vulnerability']} ({issue['severity']})")
```

### `parse_semgrep_results(semgrep_results, tool_version)`

Parse Semgrep results into a list of issues.

**Parameters:**
- `semgrep_results` (dict): Results returned from Semgrep
- `tool_version` (str): Version of Semgrep used

**Returns:**
- `list`: List of standardized issue dictionaries

**Notes:**
- Handles the special case where Semgrep was skipped due to platform compatibility

**Example:**
```python
semgrep_results = run_semgrep('/path/to/my_project')
issues = parse_semgrep_results(semgrep_results, get_tool_version('semgrep'))
for issue in issues:
    print(f"{issue['package']}: {issue['vulnerability']} ({issue['severity']})")
```

## Output Functions

### `format_issue_as_string(issue)`

Format a single issue as a string.

**Parameters:**
- `issue` (dict): A standardized issue dictionary

**Returns:**
- `str`: Formatted string representation of the issue

**Example:**
```python
formatted_issue = format_issue_as_string({
    'tool': 'Bandit 1.7.4',
    'package': 'app.py:42',
    'vulnerability': 'B301',
    'severity': 'MEDIUM',
    'description': 'Pickle module is used which is unsafe'
})
print(formatted_issue)
```

### `format_table(issues, missing_tools=None)`

Format the results into a text table.

**Parameters:**
- `issues` (list): List of standardized issue dictionaries
- `missing_tools` (list, optional): List of tools that couldn't be run

**Returns:**
- `str`: Formatted table as a string

**Example:**
```python
all_issues = []
all_issues.extend(parse_safety_results(run_safety('django'), get_tool_version('safety')))
all_issues.extend(parse_pip_audit_results(run_pip_audit('django'), get_tool_version('pip-audit')))
missing_tools = ['semgrep']  # Example of a missing tool

table = format_table(all_issues, missing_tools)
print(table)
```

### `save_report(results_text, issues, package_name_or_path, missing_tools=None, path_based_tools_excluded=None, semgrep_excluded=None)`

Save the results to a file.

**Parameters:**
- `results_text` (str): Formatted text results
- `issues` (list): List of standardized issue dictionaries
- `package_name_or_path` (str): Package name or path that was checked
- `missing_tools` (list, optional): List of tools that couldn't be run
- `path_based_tools_excluded` (list, optional): Tools excluded due to path issues
- `semgrep_excluded` (bool, optional): Whether Semgrep was excluded due to platform

**Returns:**
- `str`: Name of the report file that was created

**Notes:**
- Creates a timestamped file name based on the package name
- Includes additional sections for missing tools and path limitations
- Adds a reference section explaining each security tool

**Example:**
```python
results_text, issues, missing_tools, excluded_tools, semgrep_excluded = check_package_security('requests')
filename = save_report(results_text, issues, 'requests', missing_tools, excluded_tools, semgrep_excluded)
print(f"Report saved to: {filename}")
```

## Utility Functions

### `main()`

Main entry point for the command-line script.

**Parameters:**
- None (uses command-line arguments)

**Returns:**
- None

**Notes:**
- Parses command-line arguments using argparse
- Sets up optional global timeout
- Calls check_package_security with appropriate arguments
- Prints results and optionally saves to a file

**Example:**
```
# Called when running the script directly:
python PyDefender.py requests --exclude semgrep --no-save
```
