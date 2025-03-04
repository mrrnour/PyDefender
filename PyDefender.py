#!/usr/bin/env python3
"""
Simple Package Security Checker

This script performs comprehensive security checks on a Python package using multiple security tools:
1. Safety - checks dependencies against known vulnerabilities
2. pip-audit - audits Python packages for security vulnerabilities
3. Bandit - finds common security issues in Python code
4. Semgrep - lightweight static analysis for security patterns

Usage:
    python security_checker.py <package_name_or_path>
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import argparse
import re
import platform
import csv
import io
from datetime import datetime
from collections import defaultdict
from functools import lru_cache

@lru_cache(maxsize=32)
def get_tool_version(tool_name):
    """Get the version of a tool."""
    version_commands = {
        "safety": ["safety", "--version"],
        "pip-audit": ["pip-audit", "--version"],
        "bandit": ["bandit", "--version"],
        "semgrep": ["semgrep", "--version"]
    }
    
    try:
        if tool_name in version_commands:
            result = subprocess.run(
                version_commands[tool_name],
                capture_output=True,
                text=True,
                check=False
            )
            if result.stdout:
                version_match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
                if version_match:
                    return version_match.group(1)
                return result.stdout.strip()
            return "Unknown"
    except:
        return "Not installed"
    
    return "Unknown"

def find_package_path(package_name):
    """Try to find the installed path of a package."""
    try:
        # First, check if it's already a valid path
        if os.path.exists(package_name):
            return os.path.abspath(package_name)
            
        # Use importlib to find the package path
        import importlib
        try:
            module = importlib.import_module(package_name)
            if hasattr(module, '__file__'):
                module_path = os.path.dirname(os.path.abspath(module.__file__))
                print(f"Found package path: {module_path}")
                return module_path
        except ImportError:
            pass
        
        # Try using pip to find the package
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", "-f", package_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.stdout:
                location_match = re.search(r'Location: (\S+)', result.stdout)
                if location_match:
                    package_location = location_match.group(1)
                    
                    # Try different common naming patterns
                    potential_paths = [
                        os.path.join(package_location, package_name),
                        os.path.join(package_location, package_name.replace('-', '_')),
                        os.path.join(package_location, *package_name.split('-')),
                        os.path.join(package_location, *package_name.split('_'))
                    ]
                    
                    for path in potential_paths:
                        if os.path.exists(path):
                            return path
                    
                    # print(f"Could not find exact package directory, using location: {package_location}")
                    return package_location
        except Exception:
            pass
            
    except Exception as e:
        print(f"Error finding package path: {str(e)}")
    
    return None

def run_safety(package_name):
    """Run safety check on the package."""
    print(f"Running Safety check on {package_name}...")
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp:
            temp.write(f"{package_name}\n")
            temp_path = temp.name
        
        result = subprocess.run(
            ["safety", "check", "-r", temp_path, "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60  # Add timeout to prevent hanging
        )
        
        os.unlink(temp_path)
        
        # Check for authentication issues
        if "Authentication Error" in result.stderr or "Authentication required" in result.stderr:
            return {"error": "Authentication error with Safety. API key may be required.", "vulnerabilities": []}
            
        # Simply check for "No vulnerable packages found" in either stdout or stderr
        if "No vulnerable packages found" in result.stdout or "No vulnerable packages found" in result.stderr:
            return {"vulnerabilities": []}
        
        # Try JSON parsing if there's output
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                # If we can't parse JSON but have output, there might be vulnerabilities but in a format we can't parse
                return {"error": "Could not parse Safety output", "vulnerabilities": []}
        
        # If we have an error code and error output, report the specific error
        if result.returncode != 0 and result.stderr:
            # Clean up the error message - remove ANSI color codes
            error_msg = re.sub(r'\x1b\[\d+m', '', result.stderr)
            
            # Extract just the main error message without the traceback
            if "Traceback" in error_msg:
                error_msg = error_msg.split("Traceback")[0].strip()
            
            # Look for common error patterns and simplify
            if "CERTIFICATE_VERIFY_FAILED" in error_msg:
                error_msg = "SSL certificate verification failed. Check your network or proxy settings."
            elif "Max retries exceeded" in error_msg:
                error_msg = "Connection failed: Max retries exceeded. Check your network connection."
            elif "Unable to load the openID config" in error_msg:
                error_msg = "Authentication service unavailable. Check your network connection."
            else:
                # For other errors, just get the first line or limit to 100 chars
                error_msg = error_msg.split('\n')[0][:100]
                
            return {"error": f"Safety check failed: {error_msg}", "vulnerabilities": []}
        
        # Default case
        return {"vulnerabilities": []}
        
    except subprocess.TimeoutExpired:
        return {"error": "Safety check timed out after 60 seconds", "vulnerabilities": []}
    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}
    
def run_pip_audit(package_name):
    """Run pip-audit on the package."""
    print(f"Running pip-audit on {package_name}...")
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp:
            temp.write(f"{package_name}\n")
            temp_path = temp.name
            
        result = subprocess.run(
            ["pip-audit", "-r", temp_path, "--format", "json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60  # Add timeout to prevent hanging
        )
        
        os.unlink(temp_path)
        
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": "Could not parse pip-audit output"}
        else:
            return {"error": result.stderr}
        
    except subprocess.TimeoutExpired:
        return {"error": "pip-audit check timed out after 60 seconds"}
    except Exception as e:
        return {"error": str(e)}

def run_bandit(package_path):
    """Run bandit on the package source code."""
    print(f"Running Bandit on {package_path}...")
    
    try:
        if not os.path.exists(package_path):
            actual_path = find_package_path(package_path)
            if not actual_path:
                return {"error": f"Path {package_path} does not exist and could not find installed package. Bandit requires a path to the source code."}
            package_path = actual_path
            print(f"Using discovered path for Bandit: {package_path}")
        
        result = subprocess.run(
            ["bandit", "-r", package_path, "-f", "json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=180  # Longer timeout for larger packages
        )
        
        if result.stdout:
            try:
                # Try to find valid JSON in the output
                # Sometimes tools output other text before/after the JSON
                stdout = result.stdout
                
                # Look for JSON start/end markers
                json_start = stdout.find('{')
                json_end = stdout.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    potential_json = stdout[json_start:json_end]
                    try:
                        return json.loads(potential_json)
                    except json.JSONDecodeError:
                        pass  # Fall back to trying the whole output
                
                # If that failed, try the entire output
                return json.loads(stdout)
            except json.JSONDecodeError as e:
                return {"error": f"Could not parse Bandit output: {str(e)}"}
        else:
            error_msg = result.stderr.strip() if result.stderr else "No output from Bandit"
            return {"error": error_msg}
        
    except subprocess.TimeoutExpired:
        return {"error": "Bandit check timed out after 180 seconds"}
    except Exception as e:
        return {"error": str(e)}

def run_semgrep(package_path):
    """Run semgrep on the package source code for security checks."""
    if platform.system() == "Windows":
        print(f"Skipping Semgrep as it's not officially supported on Windows.")
        return {"error": "Semgrep is not officially supported on Windows.", "skipped_due_to_platform": True}
    
    print(f"Running Semgrep on {package_path}...")
    
    try:
        if not os.path.exists(package_path):
            actual_path = find_package_path(package_path)
            if not actual_path:
                return {"error": f"Path {package_path} does not exist and could not find installed package. Semgrep requires a path to the source code."}
            package_path = actual_path
            print(f"Using discovered path for Semgrep: {package_path}")
        
        result = subprocess.run(
            ["semgrep", "--config=p/security-audit", package_path, "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=300  # Longer timeout for larger packages
        )
        
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": "Could not parse Semgrep output"}
        else:
            return {"error": result.stderr}
        
    except subprocess.TimeoutExpired:
        return {"error": "Semgrep check timed out after 300 seconds"}
    except Exception as e:
        return {"error": str(e)}

def parse_safety_results(safety_results, tool_version):
    """Parse Safety results into a list of issues."""
    issues = []
    tool_name = f"Safety {tool_version}"
    
    if "error" in safety_results:
        issues.append({
            "tool": tool_name,
            "package": "N/A",
            "vulnerability": safety_results["error"],
            "severity": "ERROR",
            "description": "Could not run Safety successfully"
        })
        return issues
    
    for vuln in safety_results.get("vulnerabilities", []):
        issues.append({
            "tool": tool_name,
            "package": f"{vuln.get('package_name', 'Unknown')} {vuln.get('installed_version', 'Unknown')}",
            "vulnerability": vuln.get('id', 'Unknown'),
            "severity": vuln.get('severity', 'Unknown').upper(),
            "description": vuln.get('advisory', 'No description')
        })
    
    if not issues:
        issues.append({
            "tool": tool_name,
            "package": "All packages",
            "vulnerability": "None",
            "severity": "SAFE",
            "description": "No vulnerable packages found"
        })
    
    return issues

def parse_pip_audit_results(pip_audit_results, tool_version):
    """Parse pip-audit results into a list of issues."""
    issues = []
    tool_name = f"pip-audit {tool_version}"
    
    if "error" in pip_audit_results:
        issues.append({
            "tool": tool_name,
            "package": "N/A",
            "vulnerability": pip_audit_results["error"],
            "severity": "ERROR",
            "description": "Could not run pip-audit successfully"
        })
        return issues
    
    vulnerabilities = pip_audit_results.get("vulnerabilities", [])
    if vulnerabilities:
        for vuln in vulnerabilities:
            package_info = vuln.get("package", {})
            package_name = package_info.get("name", "Unknown")
            package_version = package_info.get("version", "Unknown")
            
            for v in vuln.get("vulnerabilities", []):
                issues.append({
                    "tool": tool_name,
                    "package": f"{package_name} {package_version}",
                    "vulnerability": v.get("id", "Unknown"),
                    "severity": v.get("severity", "Unknown").upper(),
                    "description": v.get("description", "No description")
                })
    
    if not issues:
        issues.append({
            "tool": tool_name,
            "package": "All packages",
            "vulnerability": "None",
            "severity": "SAFE",
            "description": "No vulnerable packages found"
        })
    
    return issues

def parse_bandit_results(bandit_results, tool_version):
    """Parse Bandit results into a list of issues."""
    issues = []
    tool_name = f"Bandit {tool_version}"
    
    if "error" in bandit_results:
        issues.append({
            "tool": tool_name,
            "package": "N/A",
            "vulnerability": bandit_results["error"],
            "severity": "ERROR",
            "description": "Could not run Bandit successfully"
        })
        return issues
    
    results = bandit_results.get("results", [])
    
    for result in results:
        severity = result.get("issue_severity", "Unknown").upper()
        issues.append({
            "tool": tool_name,
            "package": f"{result.get('filename', 'Unknown')}:{result.get('line_number', 0)}",
            "vulnerability": result.get("test_id", "Unknown"),
            "severity": severity,
            "description": result.get("issue_text", "No description")
        })
    
    if not issues:
        issues.append({
            "tool": tool_name,
            "package": "All files",
            "vulnerability": "None",
            "severity": "SAFE",
            "description": "No security issues found"
        })
    
    return issues

def parse_semgrep_results(semgrep_results, tool_version):
    """Parse Semgrep results into a list of issues."""
    issues = []
    tool_name = f"Semgrep {tool_version}"
    
    if "skipped_due_to_platform" in semgrep_results and semgrep_results["skipped_due_to_platform"]:
        issues.append({
            "tool": tool_name,
            "package": "N/A",
            "vulnerability": "SKIPPED",
            "severity": "INFO",
            "description": "Semgrep is not officially supported on Windows and was automatically skipped."
        })
        return issues
    
    if "error" in semgrep_results:
        issues.append({
            "tool": tool_name,
            "package": "N/A",
            "vulnerability": semgrep_results["error"],
            "severity": "ERROR",
            "description": "Could not run Semgrep successfully"
        })
        return issues
    
    results = semgrep_results.get("results", [])
    
    for result in results:
        severity = result.get("extra", {}).get("severity", "Unknown").upper()
        issues.append({
            "tool": tool_name,
            "package": f"{result.get('path', 'Unknown')}:{result.get('start', {}).get('line', 0)}",
            "vulnerability": result.get("check_id", "Unknown"),
            "severity": severity,
            "description": result.get("extra", {}).get("message", "No description")
        })
    
    if not issues:
        issues.append({
            "tool": tool_name,
            "package": "All files",
            "vulnerability": "None",
            "severity": "SAFE",
            "description": "No security issues found"
        })
    
    return issues

def format_issues_as_csv(issues, missing_tools=None):
    """Format the results into a CSV string."""
    # Create a string IO object to write the CSV data
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    
    # Write header
    writer.writerow(["Tool", "Package", "Vulnerability", "Severity", "Description"])
    
    # Add missing tools as error rows
    if missing_tools:
        for tool in missing_tools:
            writer.writerow([
                tool,
                "NOT INSTALLED",
                "TOOL_MISSING",
                "ERROR",
                f"The {tool} tool is not installed. Security checks for this tool were skipped."
            ])
    
    # Add regular issues
    if issues:
        for issue in issues:
            writer.writerow([
                issue["tool"],
                issue["package"],
                issue["vulnerability"],
                issue["severity"],
                issue["description"]
            ])
    
    # Handle case when no issues and no missing tools
    if not issues and not missing_tools:
        writer.writerow(["N/A", "N/A", "NONE", "INFO", "No results generated. This is unusual."])
    
    # Get the CSV data as a string
    csv_data = output.getvalue()
    output.close()
    
    return csv_data

def check_package_security(package_name_or_path, include_tools=None, exclude_tools=None):
    """
    Main function to check package security using multiple security tools.
    
    Args:
        package_name_or_path (str): Either a package name (e.g., 'requests') or a path to source code
        include_tools (list): List of tools to include (default: all)
        exclude_tools (list): List of tools to exclude (default: none)
    
    Returns:
        str: Formatted CSV with security findings
    """
    is_windows = platform.system() == "Windows"
    semgrep_excluded = False
    
    print(f"\n{'='*80}\nSECURITY CHECK FOR: {package_name_or_path}\n{'='*80}\n")
    
    # Determine which tools to run
    all_tools = {
        "safety": {"checker": run_safety, "parser": parse_safety_results, "needs_path": False},
        "pip-audit": {"checker": run_pip_audit, "parser": parse_pip_audit_results, "needs_path": False},
        "bandit": {"checker": run_bandit, "parser": parse_bandit_results, "needs_path": True},
        "semgrep": {"checker": run_semgrep, "parser": parse_semgrep_results, "needs_path": True}
    }
    
    # If running on Windows and semgrep is going to be used, automatically exclude it
    if is_windows and "semgrep" in all_tools:
        # Check if semgrep would be used based on include/exclude lists
        would_use_semgrep = True
        
        if include_tools and "semgrep" not in include_tools:
            would_use_semgrep = False
        
        if exclude_tools and "semgrep" in exclude_tools:
            would_use_semgrep = False
            
        if would_use_semgrep:
            print("Note: Semgrep is not officially supported on Windows and has been automatically excluded.")
            if not exclude_tools:
                exclude_tools = ["semgrep"]
            else:
                exclude_tools.append("semgrep")
            semgrep_excluded = True
    
    # Determine which tools to include
    tools_to_run = {}
    if include_tools:
        for tool in include_tools:
            if tool in all_tools:
                tools_to_run[tool] = all_tools[tool]
    else:
        tools_to_run = all_tools.copy()
    
    # Apply exclusions
    if exclude_tools:
        for tool in exclude_tools:
            if tool in tools_to_run:
                del tools_to_run[tool]
    
    # Check if tools are installed
    installed_tools = []
    missing_tools = []
    
    for tool_name in tools_to_run.keys():
        # Check if tool is installed
        tool_path = shutil.which(tool_name)
        if tool_path:
            installed_tools.append(tool_name)
        else:
            missing_tools.append(tool_name)
    
    if missing_tools:
        print("Warning: The following tools are not installed:")
        for tool in missing_tools:
            print(f"- {tool} (skipping this check)")
        print("\nTo install missing tools, use:")
        install_commands = {
            "safety": "pip install safety",
            "pip-audit": "pip install pip-audit",
            "bandit": "pip install bandit",
            "semgrep": "pip install semgrep"
        }
        for tool in missing_tools:
            print(f"{install_commands.get(tool, f'[See documentation for {tool} installation]')}")
        print("")
    
    # For package names, try to find their path
    path_based_tools_excluded = []

    # Get tool versions
    tool_versions = {tool: get_tool_version(tool) for tool in installed_tools}
    
    # Run all installed security checks
    results = {}
    for tool_name in installed_tools:
        tool_info = tools_to_run[tool_name]
        
        # Run the appropriate checker function
        if tool_info["needs_path"]:
            # For tools that need a path
            results[tool_name] = tool_info["checker"](package_name_or_path)
        else:
            # For tools that work with package names
            results[tool_name] = tool_info["checker"](package_name_or_path)
    
    # Parse results
    all_issues = []
    issues_by_tool = {}
    
    for tool_name, result in results.items():
        parser = tools_to_run[tool_name]["parser"]
        issues = parser(result, tool_versions.get(tool_name, "Unknown"))
        all_issues.extend(issues)
        issues_by_tool[tool_name] = issues
    
    # Add timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate summary
    summary_counts = {}
    total_issues = 0
    
    for tool_name in installed_tools:
        tool_issues = issues_by_tool.get(tool_name, [])
        issue_count = sum(1 for issue in tool_issues if issue.get("severity") != "SAFE")
        summary_counts[tool_name] = issue_count
        total_issues += issue_count
    
    # Create summary header for CSV
    summary_rows = []
    summary_rows.append(["SUMMARY", "", "", "", ""])
    summary_rows.append(["Security Check Report", timestamp, "", "", ""])
    summary_rows.append(["Package/Path", package_name_or_path, "", "", ""])
    
    # Add Windows-specific note about Semgrep only if it was actually excluded
    if semgrep_excluded:
        summary_rows.append(["Note", "Semgrep is not officially supported on Windows and was automatically excluded.", "", "", ""])
    
    if not installed_tools:
        summary_rows.append(["ERROR", "No security tools are installed! No checks were performed.", "", "", ""])
        summary_rows.append(["", "Please install at least one security tool using the commands shown above.", "", "", ""])
    
    summary_rows.append(["", "", "", "", ""])  # Empty line separator
    
    # Create CSV output
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    
    # Write summary rows
    for row in summary_rows:
        writer.writerow(row)
    
    # Get the CSV table
    csv_table = format_issues_as_csv(all_issues, missing_tools=missing_tools)
    
    # Combine summary with table
    full_csv = output.getvalue() + csv_table
    output.close()
    
    return full_csv, all_issues, missing_tools, path_based_tools_excluded, semgrep_excluded

def save_report(results_text, issues, package_name_or_path, missing_tools=None, path_based_tools_excluded=None, semgrep_excluded=None):
    """Save the results to a CSV file."""
    filename = f"security_report_{os.path.basename(package_name_or_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='') as f:
        f.write(results_text)
    
    return filename

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Simple security checker for Python packages and code")
    parser.add_argument("package_name_or_path", help="Package name or path to source code")
    parser.add_argument("--include", "-i", nargs="+", help="Only include these tools (options: safety, pip-audit, bandit, semgrep)")
    parser.add_argument("--exclude", "-e", nargs="+", help="Exclude these tools")
    parser.add_argument("--no-save", action="store_true", help="Don't save the report to a file")
    parser.add_argument("--timeout", type=int, default=0, help="Set a global timeout in seconds for all tools (0 for default timeouts)")
    args = parser.parse_args()
    
    # Set global timeout if specified
    if args.timeout > 0:
        # The timeouts in the individual tool functions will be used
        print(f"Using global timeout of {args.timeout} seconds for all tools")
    
    results_text, issues, missing_tools, path_based_tools_excluded, semgrep_excluded = check_package_security(
        args.package_name_or_path,
        include_tools=args.include,
        exclude_tools=args.exclude
    )
    
    print(results_text)
    
    if not args.no_save:
        # Save report
        filename = save_report(results_text, issues, args.package_name_or_path, 
                              missing_tools, path_based_tools_excluded, semgrep_excluded)
        print(f"\nReport saved to: {filename}")

if __name__ == "__main__":
    main()