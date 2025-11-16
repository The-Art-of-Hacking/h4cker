# H4cker Cybersecurity Resources Repository

The h4cker repository is a comprehensive collection of cybersecurity references, scripts, tools, code, and educational resources. It serves as supplemental material for cybersecurity books, video courses, and live training created by Omar Santos.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Prerequisites and Environment Setup
- Python 3.12+ is available and working
- Node.js 20.19+ is available and working  
- Docker 28.0+ is available and working
- Repository is a collection of cybersecurity resources, NOT a traditional application that builds into a single artifact

### Core Validation Commands
- Link checking (primary CI validation): `lychee --config lychee.toml --no-progress --verbose './**/*.md'` -- takes 15-30 seconds. NEVER CANCEL. Set timeout to 60+ seconds.
- Install link checker if missing: `curl -L https://github.com/lycheeverse/lychee/releases/latest/download/lychee-x86_64-unknown-linux-gnu.tar.gz | tar -xz && sudo mv lychee /usr/local/bin/`

### Python Scripts and Tools Validation  
- Install OSINT tool dependencies: `cd osint/quick_recon && pip3 install -r requirements.txt` -- takes 10-20 seconds. NEVER CANCEL.
- Install common dependencies: `pip3 install python-nmap requests termcolor colorama beautifulsoup4` -- takes 15-30 seconds. NEVER CANCEL.
- Install system tools as needed: `sudo apt-get update && sudo apt-get install -y nmap` -- takes 60-120 seconds. NEVER CANCEL. Set timeout to 180+ seconds.

### Docker Security Examples
- Build Docker security examples: `cd docker-and-k8s-security/docker && make build-naive` -- takes 20-30 seconds for first build. NEVER CANCEL. Set timeout to 300+ seconds for initial builds.
- Other Docker targets: `make build-non-root`, `make build-distroless`, `make run`
- Docker builds may take up to 5 minutes on first run due to image downloads. NEVER CANCEL.

## Validation Scenarios

### Repository Health Check
Always run these commands to validate repository state:
1. `lychee --config lychee.toml --no-progress --verbose './README.md'` -- Test core documentation links
2. `cd osint/quick_recon && pip3 install -r requirements.txt` -- Verify Python dependencies
3. `cd docker-and-k8s-security/docker && make build-naive` -- Test Docker functionality

### Script Testing Scenarios  
- Test Python scripts individually as most require specific network access or targets
- Many scripts are designed for penetration testing environments and may not run fully in restricted environments
- Focus on syntax validation and dependency checking rather than full execution
- Example: `python3 -m py_compile programming-and-scripting-for-cybersecurity/recon_scripts/scanning/basic_ping_sweep.py`

### Documentation Updates
- Always run link checking after modifying markdown files: `lychee --config lychee.toml --no-progress --verbose './**/*.md'`
- Links to external sites may fail due to network restrictions - this is expected
- Focus on internal repository links and file references

## Repository Structure Overview

### Key Directories
- `programming-and-scripting-for-cybersecurity/` - Educational scripts in Python, Bash, etc.
- `osint/` - Open Source Intelligence tools and resources
- `docker-and-k8s-security/` - Container security examples and tools
- `threat-hunting/` - Threat hunting resources and techniques
- `exploit-development/` - Exploit development resources
- `web-application-testing/` - Web security testing resources
- `dfir/` - Digital Forensics and Incident Response materials
- `cheat-sheets/` - Quick reference guides

### Working with Individual Tools
- Each directory contains specialized tools for different cybersecurity domains
- Tools are meant to be used individually rather than as part of a larger application
- Many tools require network access to external services (may not work in restricted environments)
- Focus on code review, syntax checking, and educational value rather than live execution

## Common Tasks

### Repository Health Check (Complete Validation Scenario)
Run this complete validation sequence after making changes:
```bash
cd /home/runner/work/h4cker/h4cker
echo "1. Testing link checker..."
lychee --config lychee.toml --no-progress --verbose './README.md' 
echo "2. Testing Python dependencies..."
cd osint/quick_recon && pip3 install -r requirements.txt
echo "3. Testing Docker functionality..."
cd /home/runner/work/h4cker/h4cker/docker-and-k8s-security/docker && make build-naive
```
Expected results: Links mostly pass (external sites may fail), Python deps install successfully, Docker builds complete.

### Adding New Resources
- Place new scripts in appropriate domain directories (`programming-and-scripting-for-cybersecurity/`, `osint/`, etc.)
- Update documentation to reference new resources
- Run link checking to validate any new markdown content: `lychee --config lychee.toml --no-progress --verbose './**/*.md'`
- Test script syntax: `python3 -m py_compile path/to/script.py`
- Validate script has proper documentation and educational comments

### Testing Individual Scripts
- Syntax validation: `python3 -m py_compile path/to/script.py`
- Basic execution test (if safe): `python3 path/to/script.py --help` 
- Dependency check: Look for import statements and ensure packages are available
- Many scripts require specific network targets or lab environments - focus on syntax and educational value

### Testing Changes  
- Run link checking on modified markdown files: `lychee --config lychee.toml --no-progress --verbose 'path/to/modified.md'`
- Validate Python syntax for modified scripts: `python3 -m py_compile script.py` 
- Test Docker builds if modifying container examples: `cd docker-and-k8s-security/docker && make build-TARGET`
- Review scripts for educational value and proper documentation

### CI/CD Integration
The repository uses GitHub Actions with these workflows:
- `.github/workflows/link-check.yml` - Validates markdown links on pull requests
- Uses lychee configuration from `lychee.toml`
- No traditional build/test pipeline as this is a resource collection

## Important Notes

### What This Repository IS
- Educational cybersecurity resource collection
- Reference scripts and tools for learning
- Docker security examples and demonstrations
- Documentation and cheat sheets

### What This Repository IS NOT
- A deployable application or service
- A package that gets installed system-wide  
- A traditional software project with comprehensive test suites
- A single tool or application

### Network and Security Considerations
- Many scripts are designed for penetration testing and may trigger security tools
- Scripts often require network access to external services
- Some tools are meant for use in isolated lab environments
- Focus on educational and research purposes

### Timing Expectations
- Link checking: 15-30 seconds (NEVER CANCEL - set 60+ second timeout)
- Python dependency installation: 10-30 seconds (NEVER CANCEL - set 60+ second timeout)  
- Docker builds: 20-300 seconds depending on base images (NEVER CANCEL - set 300+ second timeout)
- System package installation: 60-180 seconds (NEVER CANCEL - set 300+ second timeout)
- Individual script validation: 5-60 seconds depending on complexity

Always wait for commands to complete fully. Builds and installations may take several minutes, especially on first run.

## Troubleshooting Common Issues

### Link Checker Failures
- External links often fail due to network restrictions - this is expected
- Focus on internal repository links (file:// paths should all pass)
- Exclude problematic external links in `lychee.toml` if needed

### Python Script Issues  
- Many scripts require network access or specific targets (may fail in restricted environments)
- Scripts may have bugs (like string formatting issues) - focus on syntax validation and educational value
- Install missing dependencies: `pip3 install package-name`
- Use `python3 -m py_compile script.py` for syntax-only validation

### Docker Build Issues
- First builds take longer due to image downloads (up to 5 minutes)
- Use appropriate timeouts (300+ seconds) for initial builds
- Cached builds are much faster (5-30 seconds)

### Environment Limitations
- Network access is restricted - many cybersecurity tools won't run fully
- Focus on code review, syntax validation, and educational aspects
- Test individual components rather than complete workflows