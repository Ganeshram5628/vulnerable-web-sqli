import os
import json
import asyncio
import subprocess
import tempfile
import shutil 
import aiohttp
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import requests
import git
from security_models import RiskLevel, Action, CVEInfo, VulnerabilityFinding
import uuid
import re
import sys
# Ensure project root is importable so we can import newwithidor.py from parent directory
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
try:
    # Use centralized IDOR implementation
    from newwithidor import EnhancedSecurityScanner as IDORScanner
except Exception:
    IDORScanner = None

 
class EnhancedSecurityScanner:
    def __init__(self, config_path: str = None):
        self.config = self.load_config(config_path)
        self.cve_cache = {}  # Cache CVE lookups to avoid API rate limits
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'sca': {},
            'secrets': {},
            'sast': {},
            'idor': {},
            'sbom': {},
            'summary': {},
            'risk_assessment': {},
            'recommendations': []
        }
        # Track if we created a temporary requirements file
        self.temp_requirements_created = False
        self.temp_requirements_path = None
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration with enhanced CVE-based thresholds and IDOR detection"""
        default_config = {
            'tools': {
                'sca': 'safety',
                'secrets': 'gitleaks',
                'sast': 'bandit',
                'idor': 'semgrep'
            },
            'risk_thresholds': {
                # CVE Score based thresholds
                'critical_cvss_min': 9.0,      
                'high_cvss_min': 7.0,          
                'medium_cvss_min': 4.0,        
                'low_cvss_min': 0.1,           
                
                # Action thresholds
                'block_on_critical': True,      
                'block_on_high_count': 5,       
                'warn_on_medium_count': 10,     
                
                # Age-based risk adjustment
                'recent_cve_days': 30,          
                'exploit_multiplier': 1.5,      
                
                # Secrets thresholds
                'secrets_max_findings': 0,      
                
                # SAST thresholds by type
                'sast_critical_types': ['sql_injection', 'code_injection', 'xss'],
                'sast_high_types': ['hardcoded_password', 'weak_crypto'],
            },
            'cve_sources': {
                'nvd_api_key': None,  # Optional NVD API key for higher rate limits
                'use_offline_db': False,  # Use local CVE database if available
            },
            'semgrep_config': {
                'rulesets': [
                    'p/owasp-top-10',
                    'p/security-audit',
                    'p/insecure-transport',
                ],
                'custom_idor_rules': True,
                'timeout': 300,
            },
            'report_format': 'json'
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config

    async def get_cve_info(self, cve_id: str) -> Optional[CVEInfo]:

        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]
        
        try:
            # NVD API v2.0
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            headers = {}
            if self.config['cve_sources']['nvd_api_key']:
                headers['apiKey'] = self.config['cve_sources']['nvd_api_key']
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('vulnerabilities'):
                            vuln_data = data['vulnerabilities'][0]['cve']
                            
                            # Extract CVSS score
                            cvss_score = 0.0
                            cvss_vector = ""
                            exploitability_score = 0.0
                            impact_score = 0.0
                            
                            # Try CVSS v3.1 first, then v3.0, then v2.0
                            metrics = vuln_data.get('metrics', {})
                            if 'cvssMetricV31' in metrics:
                                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                                exploitability_score = cvss_data.get('exploitabilityScore', 0.0)
                                impact_score = cvss_data.get('impactScore', 0.0)
                            elif 'cvssMetricV30' in metrics:
                                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                            elif 'cvssMetricV2' in metrics:
                                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                                cvss_score = cvss_data['baseScore']
                                cvss_vector = cvss_data['vectorString']
                            
                            # Determine severity based on score
                            if cvss_score >= 9.0:
                                severity = "CRITICAL"
                            elif cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                            
                            # Extract references
                            references = []
                            for ref in vuln_data.get('references', []):
                                references.append(ref['url'])
                            
                            cve_info = CVEInfo(
                                cve_id=cve_id,
                                cvss_score=cvss_score,
                                cvss_vector=cvss_vector,
                                severity=severity,
                                description=vuln_data['descriptions'][0]['value'],
                                published_date=vuln_data['published'],
                                last_modified=vuln_data['lastModified'],
                                references=references,
                                exploitability_score=exploitability_score,
                                impact_score=impact_score
                            )
                            
                            self.cve_cache[cve_id] = cve_info
                            return cve_info
                    
                    # Rate limiting - wait if needed
                    elif response.status == 429:
                        await asyncio.sleep(1)
                        
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None

    def calculate_risk_level(self, cve_info: Optional[CVEInfo], context: Dict = None) -> Tuple[RiskLevel, Action, str]:
        
        if not cve_info:
            return RiskLevel.LOW, Action.IGNORE, "No CVE information available"
        
        score = cve_info.cvss_score
        reasoning_parts = [f"CVSS Score: {score}"]
        
        # Age-based risk adjustment
        if cve_info.published_date:
            try:
                pub_date = datetime.fromisoformat(cve_info.published_date.replace('Z', '+00:00'))
                days_old = (datetime.now().replace(tzinfo=pub_date.tzinfo) - pub_date).days
                
                if days_old <= self.config['risk_thresholds']['recent_cve_days']:
                    score += 1.0  # Increase risk for recent CVEs
                    reasoning_parts.append(f"Recent CVE (published {days_old} days ago)")
            except:
                pass
        
        # Exploitability adjustment
        if cve_info.exploitability_score > 8.0:
            score *= self.config['risk_thresholds']['exploit_multiplier']
            reasoning_parts.append("High exploitability score")
        
        # Context-based adjustments
        if context:
            # Production environment gets higher risk
            if context.get('environment') == 'production':
                score += 0.5
                reasoning_parts.append("Production environment")
            
            # Internet-facing services get higher risk
            if context.get('internet_facing', False):
                score += 0.5
                reasoning_parts.append("Internet-facing service")
        
        # Determine risk level and action
        if score >= self.config['risk_thresholds']['critical_cvss_min']:
            risk_level = RiskLevel.CRITICAL
            action = Action.BLOCK if self.config['risk_thresholds']['block_on_critical'] else Action.WARN
        elif score >= self.config['risk_thresholds']['high_cvss_min']:
            risk_level = RiskLevel.HIGH
            action = Action.WARN
        elif score >= self.config['risk_thresholds']['medium_cvss_min']:
            risk_level = RiskLevel.MEDIUM
            action = Action.MONITOR
        else:
            risk_level = RiskLevel.LOW
            action = Action.IGNORE
        
        reasoning = "; ".join(reasoning_parts)
        return risk_level, action, reasoning

    async def run_enhanced_sca_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced SCA with mandatory SBOM generation and temp requirements creation"""
        print("Running Enhanced SCA (Software Composition Analysis) with mandatory SBOM...")
        
        sca_results = {
            'tool': self.config['tools']['sca'],
            'vulnerabilities': [],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None,
            'sbom_generated': True,
            'temp_requirements_created': False
        }
        
        try:
            # Step 1: Always generate SBOM first (this is now mandatory)
            print("  → Generating SBOM from all dependency sources...")
            sbom_result = self.generate_comprehensive_sbom(repo_path)
            self.results['sbom'] = sbom_result
            
            # Step 2: Check for existing requirements.txt files
            existing_req_files = list(Path(repo_path).rglob('requirements*.txt'))
            
            # Step 3: If no requirements.txt exists, create temporary one from SBOM
            requirements_file_to_use = None
            
            if not existing_req_files:
                print("  → No requirements.txt found, creating temporary requirements from SBOM...")
                requirements_file_to_use = self.create_temp_requirements_from_sbom(repo_path, sbom_result)
                if requirements_file_to_use:
                    self.temp_requirements_created = True
                    self.temp_requirements_path = requirements_file_to_use
                    sca_results['temp_requirements_created'] = True
                    print(f"  → Temporary requirements.txt created: {requirements_file_to_use}")
                else:
                    # Fallback to OSV if we can't create requirements file
                    return await self.fallback_to_osv_scan(sbom_result, sca_results)
            else:
                requirements_file_to_use = str(existing_req_files[0])
                print(f"  → Using existing requirements file: {requirements_file_to_use}")
            
            # Step 4: Run Safety scan with the requirements file
            print("  → Running Safety scan...")
            result = subprocess.run([
                'safety', 'check', '--json', '--file', requirements_file_to_use
            ], capture_output=True, text=True, cwd=repo_path)
            
            # Step 5: Process Safety results
            if result.returncode != 0 and result.stdout:
                try:
                    vulnerabilities = json.loads(result.stdout)
                    sca_results['vulnerabilities'] = vulnerabilities
                    
                    # Process each vulnerability with CVE scoring
                    for vuln in vulnerabilities:
                        cve_id = None
                        for id_item in vuln.get('ids', []):
                            if id_item.startswith('CVE-'):
                                cve_id = id_item
                                break
                        cve_info = None
                        if cve_id:
                            cve_info = await self.get_cve_info(cve_id)
                        risk_level, action, reasoning = self.calculate_risk_level(cve_info)
                        finding = VulnerabilityFinding(
                            tool='safety',
                            vulnerability_id=cve_id or vuln.get('id', 'Unknown'),
                            package_name=vuln.get('package', 'Unknown'),
                            current_version=vuln.get('installed_version', 'Unknown'),
                            fixed_version=vuln.get('fixed_in', None),
                            cve_info=cve_info,
                            risk_level=risk_level,
                            action=action,
                            reasoning=reasoning
                        )
                        sca_results['findings'].append(finding.__dict__)
                        sca_results['risk_summary'][risk_level.value] += 1
                        sca_results['actions'][action.value] += 1
                except json.JSONDecodeError as e:
                    print(f"  → Failed to parse Safety output: {e}")
                    return await self.fallback_to_osv_scan(sbom_result, sca_results)
            elif result.returncode == 0:
                print("  → No vulnerabilities found by Safety")
            else:
                print(f"  → Safety scan failed: {result.stderr}")
                return await self.fallback_to_osv_scan(sbom_result, sca_results)
        except Exception as e:
            print(f"  → SCA scan error: {e}")
            sca_results['status'] = 'error'
            sca_results['error'] = str(e)
        
        return sca_results

    def generate_comprehensive_sbom(self, repo_path: str) -> Dict[str, Any]:
        """Generate comprehensive SBOM from multiple dependency sources"""
        print("    → Scanning multiple dependency sources...")
        components: List[Dict[str, Any]] = []
        seen: set = set()
        sources_found: List[str] = []
        dependency_sources = {
            'requirements*.txt': self.parse_requirements_file,
            'setup.py': self.parse_setup_py,
            'pyproject.toml': self.parse_pyproject_toml,
            'Pipfile': self.parse_pipfile,
            'poetry.lock': self.parse_poetry_lock,
            'environment.yml': self.parse_conda_environment,
            'environment.yaml': self.parse_conda_environment,
        }
        for pattern, parser in dependency_sources.items():
            files = list(Path(repo_path).rglob(pattern))
            for file_path in files:
                try:
                    print(f"      → Found {file_path.name}")
                    sources_found.append(str(file_path.relative_to(repo_path)))
                    file_components = parser(file_path)
                    for comp in file_components:
                        key = (comp.get('name','').lower(), comp.get('version',''))
                        if key not in seen:
                            seen.add(key)
                            components.append(comp)
                except Exception as e:
                    print(f"      → Failed to parse {file_path}: {e}")
                    continue
        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{'vendor': 'Secure-ci-cd', 'name': 'EnhancedSecurityScanner', 'version': 'internal'}],
                'component': {'type': 'application', 'name': Path(repo_path).name},
                'sources_scanned': sources_found,
            },
            'components': components,
            'componentCount': len(components),
            'status': 'success' if components else 'empty'
        }
        print(f"    → SBOM generated: {len(components)} components from {len(sources_found)} sources")
        return bom

    def create_temp_requirements_from_sbom(self, repo_path: str, sbom_result: Dict[str, Any]) -> Optional[str]:
        """Create temporary requirements.txt file from SBOM components"""
        try:
            components = sbom_result.get('components', [])
            if not components:
                print("    → No components in SBOM to create requirements from")
                return None
            temp_req_path = Path(repo_path) / 'temp_requirements_from_sbom.txt'
            with open(temp_req_path, 'w') as f:
                f.write("# Temporary requirements.txt generated from SBOM\n")
                f.write(f"# Generated on {datetime.now().isoformat()}\n")
                f.write(f"# Found {len(components)} components\n\n")
                for comp in components:
                    name = comp.get('name')
                    version = comp.get('version')
                    if name:
                        f.write(f"{name}{'=='+version if version else ''}\n")
            print(f"    → Created temporary requirements.txt with {len(components)} packages")
            return str(temp_req_path)
        except Exception as e:
            print(f"    → Failed to create temporary requirements.txt: {e}")
            return None

    async def fallback_to_osv_scan(self, sbom_result: Dict[str, Any], sca_results: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback to OSV API scanning when Safety fails"""
        print("  → Falling back to OSV API scanning...")
        try:
            components = sbom_result.get('components', [])
            osv_findings = await self._run_osv_sca_from_sbom(components)
            for finding in osv_findings:
                sca_results['findings'].append(finding)
                risk = finding.get('risk_level') or 'LOW'
                action = finding.get('action') or 'IGNORE'
                sca_results['risk_summary'][risk] += 1
                sca_results['actions'][action] += 1
            sca_results['tool'] = 'osv'
            sca_results['status'] = 'success'
            sca_results['error'] = None
            print(f"  → OSV scan completed: {len(osv_findings)} findings")
        except Exception as e:
            sca_results['status'] = 'error'
            sca_results['error'] = f'Both Safety and OSV scanning failed: {e}'
            print(f"  → OSV fallback failed: {e}")
        return sca_results

    def parse_requirements_file(self, file_path: Path) -> List[Dict[str, Any]]:
        components: List[Dict[str, Any]] = []
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.split('#', 1)[0].strip()
                    if not line or line.startswith('-'):
                        continue
                    name, version = self.parse_package_spec(line)
                    if name:
                        components.append({'type': 'library', 'name': name, 'version': version, 'purl': f"pkg:pypi/{name}{'@'+version if version else ''}", 'source_file': str(file_path.name), 'source_line': line_num})
        except Exception as e:
            print(f"      → Error parsing {file_path}: {e}")
        return components

    def parse_setup_py(self, file_path: Path) -> List[Dict[str, Any]]:
        components: List[Dict[str, Any]] = []
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            import re
            m = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if m:
                deps_str = m.group(1)
                deps = re.findall(r'["\']([^"\']+)["\']', deps_str)
                for dep in deps:
                    name, version = self.parse_package_spec(dep)
                    if name:
                        components.append({'type': 'library', 'name': name, 'version': version, 'purl': f"pkg:pypi/{name}{'@'+version if version else ''}", 'source_file': str(file_path.name), 'source_type': 'install_requires'})
        except Exception as e:
            print(f"      → Error parsing {file_path}: {e}")
        return components

    def parse_pyproject_toml(self, file_path: Path) -> List[Dict[str, Any]]:
        return []

    def parse_pipfile(self, file_path: Path) -> List[Dict[str, Any]]:
        return []

    def parse_poetry_lock(self, file_path: Path) -> List[Dict[str, Any]]:
        return []

    def parse_conda_environment(self, file_path: Path) -> List[Dict[str, Any]]:
        return []

    def parse_package_spec(self, spec: str) -> Tuple[str, Optional[str]]:
        spec = spec.strip()
        for sep in ['===', '==', '>=', '<=', '~=', '>', '<', '!=']:
            if sep in spec:
                parts = spec.split(sep, 1)
                name = parts[0].strip()
                ver = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
                return name, ver
        return spec, None

    async def _run_osv_sca_from_sbom(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Query OSV for each PyPI component from SBOM and convert to findings."""
        findings: List[Dict[str, Any]] = []
        if not components:
            return findings
        
        async with aiohttp.ClientSession() as session:
            for comp in components:
                name = comp.get('name')
                version = comp.get('version')
                if not name or not version:
                    continue
                try:
                    payload = {
                        'package': {'ecosystem': 'PyPI', 'name': name},
                        'version': version
                    }
                    async with session.post('https://api.osv.dev/v1/query', json=payload) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        vulns = data.get('vulns', [])
                        for v in vulns:
                            cve_id = None
                            # prefer CVE id if present
                            for alias in v.get('aliases', []) or []:
                                if str(alias).startswith('CVE-'):
                                    cve_id = alias
                                    break
                            cve_info = None
                            if cve_id:
                                cve_info = await self.get_cve_info(cve_id)
                            # Fallback severity if no CVE info
                            risk_level, action, reasoning = self.calculate_risk_level(cve_info)
                            finding = {
                                'tool': 'osv',
                                'vulnerability_id': cve_id or v.get('id', 'OSV'),
                                'package_name': name,
                                'current_version': version,
                                'fixed_version': None,
                                'cve_info': cve_info.__dict__ if cve_info else None,
                                'risk_level': risk_level.value,
                                'action': action.value,
                                'reasoning': reasoning or 'OSV vulnerability detected'
                            }
                            findings.append(finding)
                except Exception:
                    # Continue with other components
                    continue
        return findings

    def run_enhanced_secrets_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced secrets scanning with risk assessment"""
        print("Running Enhanced Secrets Scanning...")
        
        secrets_results = {
            'tool': self.config['tools']['secrets'],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }
        
        try:
            # Run gitleaks
            result = subprocess.run([
                'gitleaks', 'detect', '--source', repo_path, '--report-format', 'json'
            ], capture_output=True, text=True)
            
            if result.returncode != 0 and result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    if not isinstance(findings, list):
                        findings = [findings]
                    
                    for finding in findings:
                        # Classify secret type and determine risk
                        secret_type = finding.get('RuleID', 'unknown')
                        risk_level, action = self.classify_secret_risk(secret_type, finding)
                        
                        enhanced_finding = {
                            'tool': 'gitleaks',
                            'secret_type': secret_type,
                            'file_path': finding.get('File', 'Unknown'),
                            'line_number': finding.get('StartLine', 0),
                            'risk_level': risk_level.value,
                            'action': action.value,
                            'reasoning': f"Secret type: {secret_type}",
                            'commit': finding.get('Commit', ''),
                            'description': finding.get('Description', '')
                        }
                        
                        secrets_results['findings'].append(enhanced_finding)
                        secrets_results['risk_summary'][risk_level.value] += 1
                        secrets_results['actions'][action.value] += 1
                        
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            secrets_results['status'] = 'error'
            secrets_results['error'] = str(e)
        
        return secrets_results

    def classify_secret_risk(self, secret_type: str, finding: Dict) -> Tuple[RiskLevel, Action]:
        """Classify secret risk based on type and context"""
        high_risk_secrets = [
            'aws-access-token', 'gcp-service-account', 'azure-storage-account-key',
            'private-key', 'jwt', 'database-password', 'api-key'
        ]
        
        medium_risk_secrets = [
            'github-pat', 'slack-token', 'discord-token'
        ]
        
        if any(risk_type in secret_type.lower() for risk_type in high_risk_secrets):
            return RiskLevel.CRITICAL, Action.BLOCK
        elif any(risk_type in secret_type.lower() for risk_type in medium_risk_secrets):
            return RiskLevel.HIGH, Action.WARN
        else:
            return RiskLevel.MEDIUM, Action.MONITOR

    def run_enhanced_sast_check(self, repo_path: str) -> Dict[str, Any]:
        """Enhanced SAST with risk-based classification"""
        print("Running Enhanced SAST (Static Application Security Testing)...")
        
        sast_results = {
            'tool': self.config['tools']['sast'],
            'issues': [],
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }
        
        try:
            # Run bandit for Python files
            result = subprocess.run([
                'bandit', '-r', repo_path, '-f', 'json'
            ], capture_output=True, text=True)
            
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    issues = bandit_data.get('results', [])
                    sast_results['issues'] = issues
                    
                    for issue in issues:
                        # Enhanced risk classification
                        risk_level, action = self.classify_sast_risk(issue)
                        
                        enhanced_finding = {
                            'tool': 'bandit',
                            'test_id': issue.get('test_id', 'Unknown'),
                            'test_name': issue.get('test_name', 'Unknown'),
                            'file_path': issue.get('filename', 'Unknown'),
                            'line_number': issue.get('line_number', 0),
                            'issue_severity': issue.get('issue_severity', 'UNKNOWN'),
                            'issue_confidence': issue.get('issue_confidence', 'UNKNOWN'),
                            'risk_level': risk_level.value,
                            'action': action.value,
                            'reasoning': f"Bandit severity: {issue.get('issue_severity')}, confidence: {issue.get('issue_confidence')}",
                            'description': issue.get('issue_text', ''),
                            'code': issue.get('code', '')
                        }
                        
                        sast_results['findings'].append(enhanced_finding)
                        sast_results['risk_summary'][risk_level.value] += 1
                        sast_results['actions'][action.value] += 1
                        
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            sast_results['status'] = 'error'
            sast_results['error'] = str(e)
        
        return sast_results

    def classify_sast_risk(self, issue: Dict) -> Tuple[RiskLevel, Action]:
        """Classify SAST issue risk based on severity, confidence, and type"""
        severity = issue.get('issue_severity', 'LOW')
        confidence = issue.get('issue_confidence', 'LOW')
        test_name = issue.get('test_name', '').lower()
        
        # Critical issues that should block deployment
        critical_patterns = ['sql_injection', 'code_injection', 'exec_used']
        if any(pattern in test_name for pattern in critical_patterns):
            return RiskLevel.CRITICAL, Action.BLOCK
        
        # High severity with high confidence
        if severity == 'HIGH' and confidence == 'HIGH':
            return RiskLevel.HIGH, Action.WARN
        elif severity == 'HIGH':
            return RiskLevel.MEDIUM, Action.MONITOR
        elif severity == 'MEDIUM' and confidence == 'HIGH':
            return RiskLevel.MEDIUM, Action.MONITOR
        else:
            return RiskLevel.LOW, Action.IGNORE

    async def run_security_checks(self, repo_url: str, branch: str = 'main') -> Dict[str, Any]:
        """Run all enhanced security checks with mandatory SBOM generation"""
        repo_path = None
        try:
            # Clone repository
            repo_path = self.clone_repository(repo_url, branch)
            print(f"[+] Repository cloned to: {repo_path}")
            # Step 1: Always generate comprehensive SBOM first
            print("[+] Step 1: Generating comprehensive SBOM...")
            self.results['sbom'] = self.generate_comprehensive_sbom(repo_path)
            # Debug print of SBOM
            try:
                print("[DBG] SBOM (for debugging):")
                print(json.dumps(self.results['sbom'], indent=2))
            except Exception as e:
                print(f"[DBG] Failed to pretty-print SBOM: {e}")
            # Step 2: Run security scans
            print("[+] Step 2: Running security scans...")
            sca_task = self.run_enhanced_sca_check(repo_path)
            idor_task = self.run_idor_detection(repo_path)
            with ThreadPoolExecutor(max_workers=2) as executor:
                secrets_future = executor.submit(self.run_enhanced_secrets_check, repo_path)
                sast_future = executor.submit(self.run_enhanced_sast_check, repo_path)
                self.results['sca'] = await sca_task
                self.results['idor'] = await idor_task
                self.results['secrets'] = secrets_future.result()
                self.results['sast'] = sast_future.result()
            # Step 3: Summaries
            print("[+] Step 3: Generating risk assessment...")
            self.results['summary'] = self.generate_enhanced_summary()
            self.results['risk_assessment'] = self.generate_risk_assessment()
            self.results['recommendations'] = self.generate_smart_recommendations()
            return self.results
        except Exception as e:
            error_msg = f"Security scan failed: {str(e)}"
            print(f"[-] {error_msg}")
            return {'error': error_msg, 'timestamp': datetime.now().isoformat()}
        finally:
            # Cleanup temporary files and repository
            if repo_path and os.path.exists(repo_path):
                if self.temp_requirements_created and self.temp_requirements_path:
                    try:
                        if os.path.exists(self.temp_requirements_path):
                            os.remove(self.temp_requirements_path)
                            print(f"[+] Cleaned up temporary requirements file: {self.temp_requirements_path}")
                    except Exception as e:
                        print(f"[-] Failed to cleanup temp requirements: {e}")
                shutil.rmtree(repo_path, ignore_errors=True)
                print(f"[+] Cleaned up repository: {repo_path}")

    def generate_sbom_from_requirements(self, repo_path: str) -> Dict[str, Any]:
        """Generate a minimal CycloneDX-like SBOM from requirements files.
        This avoids external dependencies by parsing requirements*.txt.
        """
        print("Generating SBOM from requirements files...")
        requirements_files: List[Path] = []
        for root, _, files in os.walk(repo_path):
            for fname in files:
                lower = fname.lower()
                if lower.startswith('requirements') and lower.endswith('.txt'):
                    requirements_files.append(Path(root) / fname)
        
        components: List[Dict[str, Any]] = []
        seen: set = set()
        
        def parse_req_line(line: str) -> Tuple[str, Optional[str]]:
            # Strip comments and options
            line = line.split('#', 1)[0].strip()
            if not line or line.startswith('-'):
                return '', None
            # Common specifiers: ==, >=, <=, ~=, >, <, ===
            for sep in ['===', '==', '>=', '<=', '~=', '>', '<']:
                if sep in line:
                    name, ver = line.split(sep, 1)
                    return name.strip(), ver.strip() or None
            # No version pinned
            return line.strip(), None
        
        for req_file in requirements_files:
            try:
                with open(req_file, 'r') as f:
                    for raw in f:
                        name, ver = parse_req_line(raw)
                        if not name:
                            continue
                        key = (name.lower(), ver or '')
                        if key in seen:
                            continue
                        seen.add(key)
                        purl = None
                        if ver:
                            purl = f"pkg:pypi/{name}@{ver}"
                        else:
                            purl = f"pkg:pypi/{name}"
                        components.append({
                            'type': 'library',
                            'name': name,
                            'version': ver,
                            'purl': purl,
                            'licenses': []
                        })
            except Exception as e:
                # Continue with other files
                print(f"SBOM: failed to read {req_file}: {e}")
                continue
        
        bom: Dict[str, Any] = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.5',
            'serialNumber': f"urn:uuid:{uuid.uuid4()}",
            'version': 1,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'tools': [{'vendor': 'Secure-ci-cd', 'name': 'EnhancedSecurityScanner', 'version': 'internal'}],
                'component': {
                    'type': 'application',
                    'name': Path(repo_path).name
                }
            },
            'components': components,
            'componentCount': len(components),
            'status': 'success' if components else 'empty'
        }
        return bom

    def clone_repository(self, repo_url: str, branch: str = 'main') -> str:
        """Clone repository to temporary directory"""
        temp_dir = tempfile.mkdtemp()
        try:
            print(f"Cloning repository: {repo_url}")
            git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            return temp_dir
        except Exception as e:
            # Cleanup temp dir if clone failed and raise a clear error
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            finally:
                raise RuntimeError(f"Failed to clone repository {repo_url} on branch {branch}: {e}")
    
    async def run_idor_detection(self, repo_path: str) -> Dict[str, Any]:
        """Delegate IDOR detection to newwithidor.EnhancedSecurityScanner if available."""
        if IDORScanner is not None:
            try:
                helper = IDORScanner()
                return await helper.run_idor_detection(repo_path)
            except Exception as e:
                # Fall back to local logic if delegation fails
                print(f"[IDOR] Delegation failed, falling back: {e}")
        # Fallback: minimal empty result structure
        return {
            'tool': self.config['tools'].get('idor', 'semgrep'),
            'findings': [],
            'risk_summary': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'actions': {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0},
            'status': 'success',
            'error': None
        }

    def classify_idor_risk(self, rule_id: str, severity: str, message: str) -> Tuple[RiskLevel, Action, str]:
        """Heuristic classification for IDOR-like findings."""
        s = severity.upper() if severity else 'LOW'
        rid = (rule_id or '').lower()
        msg = (message or '').lower()

        # Strong indicators of IDOR or access control bypass
        critical_keywords = ['insecure-direct-object', 'idor', 'missing-authorization', 'broken-access']
        high_keywords = ['exposed-identifier', 'user-controlled-id', 'path-traversal-id']

        if any(k in rid or k in msg for k in critical_keywords):
            return RiskLevel.HIGH if s in ('LOW', 'MEDIUM') else RiskLevel.CRITICAL, Action.BLOCK, 'Potential IDOR/access control bypass'
        if any(k in rid or k in msg for k in high_keywords):
            return RiskLevel.HIGH, Action.WARN, 'Identifier exposure may enable IDOR'

        if s == 'CRITICAL':
            return RiskLevel.CRITICAL, Action.BLOCK, 'Semgrep severity critical'
        if s == 'HIGH':
            return RiskLevel.HIGH, Action.WARN, 'Semgrep severity high'
        if s == 'MEDIUM':
            return RiskLevel.MEDIUM, Action.MONITOR, 'Semgrep severity medium'
        return RiskLevel.LOW, Action.IGNORE, 'Semgrep severity low'

    def create_custom_idor_rules(self, repo_path: str) -> Optional[str]:
        """Create a minimal Semgrep rules file targeting common IDOR patterns."""
        rules_yaml = """
rules:
  - id: custom.idor.parameter-usage
    patterns:
      - pattern: |
          $FUNC($REQ.$PARAM, ...)
    message: "User-controlled identifier used directly; review for authorization checks"
    severity: MEDIUM
    languages: [python, javascript, typescript]
  - id: custom.idor.missing-auth-check
    patterns:
      - pattern: |
          def $FUNC(request, ...):
            ...
            $X = request.GET["id"]
            ...
            return $RESP
    message: "Handler reads resource id from request; ensure access control checks"
    severity: HIGH
    languages: [python]
"""
        tmp_path = Path(repo_path) / f".semgrep_idor_{uuid.uuid4().hex}.yml"
        with open(tmp_path, 'w') as f:
            f.write(rules_yaml)
        return str(tmp_path)

    def extract_code_snippet(self, file_path: str, start: int, end: int, context: int = 2) -> str:
        """Safely extract a small code snippet around the finding lines."""
        try:
            full_path = Path(file_path)
            if not full_path.exists():
                return ''
            lines: List[str] = []
            with open(full_path, 'r', errors='ignore') as f:
                lines = f.readlines()
            s = max(1, (start or 1) - context)
            e = min(len(lines), (end or start or 1) + context)
            snippet = ''.join(lines[s-1:e])
            return snippet
        except Exception:
            return ''

    def get_idor_fix_guidance(self, idor_findings: List[Dict[str, Any]]) -> str:
        """Delegate to centralized guidance in newwithidor, with fallback."""
        if IDORScanner is not None:
            try:
                helper = IDORScanner()
                # newwithidor returns List[str]
                tips = helper.get_idor_fix_guidance(idor_findings)
                if isinstance(tips, list):
                    return "; ".join(tips)
            except Exception:
                pass
        return (
            "Enforce authorization checks on object access; avoid trusting identifiers from the client; "
            "use server-side ownership checks and reference maps; log and monitor sensitive access."
        )

    def generate_enhanced_summary(self) -> Dict[str, Any]:
        """Generate enhanced summary with risk-based decision making including IDOR"""
        # Aggregate risk summaries
        total_risks = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_actions = {'BLOCK': 0, 'WARN': 0, 'MONITOR': 0, 'IGNORE': 0}

        for check_type in ['sca', 'secrets', 'sast', 'idor']:
            check_results = self.results[check_type]
            risk_summary = check_results.get('risk_summary', {})
            actions = check_results.get('actions', {})
            
            for risk_level, count in risk_summary.items():
                total_risks[risk_level] += count
            
            for action, count in actions.items():
                total_actions[action] += count
        
        # Determine overall deployment decision
        overall_decision = "ALLOW"
        if total_actions['BLOCK'] > 0:
            overall_decision = "BLOCK"
        elif total_actions['WARN'] > self.config['risk_thresholds'].get('warn_threshold', 3):
            overall_decision = "WARN"
        elif total_actions['MONITOR'] > 0:
            overall_decision = "MONITOR"
        
        return {
            'total_risks': total_risks,
            'total_actions': total_actions,
            'overall_decision': overall_decision,
            'risk_score': self.calculate_overall_risk_score(total_risks),
            'deployment_recommendation': self.get_deployment_recommendation(overall_decision, total_risks),
            'idor_specific': {
                'findings_count': len(self.results.get('idor', {}).get('findings', [])),
                'critical_idor': self.results.get('idor', {}).get('risk_summary', {}).get('CRITICAL', 0),
                'high_idor': self.results.get('idor', {}).get('risk_summary', {}).get('HIGH', 0)
            }
        }

    def generate_smart_recommendations(self) -> List[Dict[str, Any]]:
        """Generate intelligent, actionable recommendations including IDOR fixes"""
        recommendations = []

        # Analyze each scan type
        for scan_type in ['sca', 'secrets', 'sast', 'idor']:
            scan_results = self.results[scan_type]
            findings = scan_results.get('findings', [])
            
            # Group by action required
            actions_needed = {}
            for finding in findings:
                action = finding.get('action', 'IGNORE')
                if action not in actions_needed:
                    actions_needed[action] = []
                actions_needed[action].append(finding)
            
            # Generate recommendations for each action type
            for action, items in actions_needed.items():
                if action == 'BLOCK' and items:
                    recommendations.append({
                        'priority': 'HIGH',
                        'title': f'Immediately remediate {len(items)} blocking {scan_type.upper()} issues',
                        'description': f'Issues require blocking action before deployment in {scan_type}',
                        'items': items[:3],  # sample
                        'estimated_effort': 'High'
                    })
                elif action == 'WARN' and items:
                    recommendations.append({
                        'priority': 'MEDIUM',
                        'title': f'Address {len(items)} high-risk {scan_type.upper()} issues',
                        'description': f'Schedule fixes for high-risk issues found in {scan_type}',
                        'items': items[:3],
                        'estimated_effort': 'Medium'
                    })

                # Add IDOR-specific guidance
                if scan_type == 'idor' and items:
                    guidance = self.get_idor_fix_guidance(items)
                    if recommendations:
                        recommendations[-1]['specific_guidance'] = guidance

        return recommendations

    def calculate_overall_risk_score(self, total_risks: Dict[str, int]) -> float:
        """Weighted score from aggregated risks."""
        weights = {'CRITICAL': 10, 'HIGH': 6, 'MEDIUM': 3, 'LOW': 1}
        score = sum(weights[k] * total_risks.get(k, 0) for k in weights)
        # Normalize to 0-100 range with a soft cap
        return float(min(100, score * 2))

    def get_deployment_recommendation(self, overall_decision: str, total_risks: Dict[str, int]) -> str:
        if overall_decision == 'BLOCK':
            return 'Do not deploy until CRITICAL/HIGH issues are remediated.'
        if total_risks.get('HIGH', 0) > 0 or total_risks.get('MEDIUM', 0) > 5:
            return 'Proceed with caution; address high/medium issues soon.'
        return 'Safe to deploy.'

    def generate_risk_assessment(self) -> Dict[str, Any]:
        """Produce auxiliary risk metrics for reporting."""
        risks = self.results.get('summary', {}).get('total_risks', {})
        factors = {
            'cve_scores_used': len(self.cve_cache),
            'recent_cves': 0,
            'high_exploitability': 0,
        }
        # Derive some simple stats from cached CVEs
        for cve in self.cve_cache.values():
            try:
                if cve.published_date:
                    pub = datetime.fromisoformat(cve.published_date.replace('Z', '+00:00'))
                    if (datetime.now().replace(tzinfo=pub.tzinfo) - pub).days <= self.config['risk_thresholds']['recent_cve_days']:
                        factors['recent_cves'] += 1
                if (cve.exploitability_score or 0) >= 2.0:
                    factors['high_exploitability'] += 1
            except Exception:
                continue
        return {
            'risk_factors': factors,
            'risk_totals': risks
        }

    # ===== IDOR support methods (ported) =====
    def analyze_idor_patterns(self) -> Dict[str, int]:
        pattern_counts = {}
        for finding in self.results.get('idor', {}).get('findings', []):
            pattern_type = finding.get('pattern_type', 'unknown')
            pattern_counts[pattern_type] = pattern_counts.get(pattern_type, 0) + 1
        return pattern_counts

    def save_enhanced_report(self, output_file: Optional[str] = None) -> str:
        """Save the full enhanced scan results to a JSON file and return the path."""
        # Default filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"enhanced_security_report_{timestamp}.json"
        # Ensure JSON serializable
        report_data = json.loads(json.dumps(self.results, default=str))
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"Enhanced security report saved to: {output_file}")
        return output_file


# Integration function for webhook handler
async def trigger_enhanced_security_scan(repo_name: str, branch: str, commit_id: str, 
                                       clone_url: str = None, context: Dict = None) -> Dict[str, Any]:
    """Enhanced security scan with CVE-based risk assessment"""
    print(f"[+] Starting enhanced security scan for {repo_name}:{branch} @ {commit_id}")
    
    if not clone_url:
        clone_url = f"https://github.com/{repo_name}.git"
    
    scanner = EnhancedSecurityScanner()
    
    try:
        results = await scanner.run_security_checks(clone_url, branch)
        
        # Add metadata
        results['metadata'] = {
            'repository': repo_name,
            'branch': branch,
            'commit_id': commit_id,
            'scan_trigger': 'webhook_push',
            'context': context or {}
        }
        
        # Save enhanced report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_safe_name = repo_name.replace('/', '_')
        report_filename = f"enhanced_security_report_{repo_safe_name}_{branch}_{timestamp}.json"
        scanner.save_enhanced_report(report_filename)
        
        # Enhanced logging
        summary = results['summary']
        print(f"[+] Enhanced security scan completed for {repo_name}")
        print(f"    Overall Decision: {summary['overall_decision']}")
        print(f"    Risk Score: {summary['risk_score']:.1f}/100")
        print(f"    Deployment: {summary['deployment_recommendation']}")
        
        # Print risk breakdown
        risks = summary['total_risks']
        print(f"    Risk Breakdown: Critical({risks['CRITICAL']}) High({risks['HIGH']}) Medium({risks['MEDIUM']}) Low({risks['LOW']})")
        
        # Print actionable recommendations
        if results['recommendations']:
            print(f"[!] Recommendations:")
            for rec in results['recommendations'][:3]:  # Show top 3
                print(f"    {rec['priority']}: {rec['title']}")
        
        return results
        
    except Exception as e:
        error_msg = f"Enhanced security scan failed for {repo_name}: {str(e)}"
        print(f"[-] {error_msg}")
        return {
            'error': error_msg,
            'metadata': {
                'repository': repo_name,
                'branch': branch,
                'commit_id': commit_id,
                'scan_trigger': 'webhook_push'
            }
        }


if __name__ == "__main__":
    # Example usage with enhanced scanning
    async def main():
        scanner = EnhancedSecurityScanner()
        
        # Test with a repository
        repo_url = "https://github.com/Ganeshram5628/vulnerable-web-sqli"
        print("🔍 Starting Enhanced Security Scan with CVE Analysis...")
        print("=" * 60)
        
        results = await scanner.run_security_checks(repo_url)
        scanner.save_enhanced_report()
        
        # Print comprehensive summary
        print("\n" + "=" * 60)
        print("📊 ENHANCED SECURITY SCAN RESULTS")
        print("=" * 60)
        
        summary = results['summary']
        print(f"Overall Decision: {summary['overall_decision']}")
        print(f"Risk Score: {summary['risk_score']:.1f}/100")
        print(f"Deployment Recommendation: {summary['deployment_recommendation']}")
        
        print(f"\n📈 Risk Breakdown:")
        risks = summary['total_risks']
        for level, count in risks.items():
            if count > 0:
                print(f"  {level}: {count} issues")
        
        print(f"\n⚡ Actions Required:")
        actions = summary['total_actions']
        for action, count in actions.items():
            if count > 0:
                print(f"  {action}: {count} items")
        
        # Show CVE details if available
        if scanner.cve_cache:
            print(f"\n🔗 CVE Analysis:")
            print(f"  Total CVEs analyzed: {len(scanner.cve_cache)}")
            critical_cves = [cve for cve in scanner.cve_cache.values() if cve.cvss_score >= 9.0]
            high_cves = [cve for cve in scanner.cve_cache.values() if 7.0 <= cve.cvss_score < 9.0]
            
            if critical_cves:
                print(f"  Critical CVEs (CVSS ≥ 9.0): {len(critical_cves)}")
                for cve in critical_cves[:3]:  # Show top 3
                    print(f"    - {cve.cve_id}: CVSS {cve.cvss_score} ({cve.severity})")
            
            if high_cves:
                print(f"  High CVEs (CVSS 7.0-8.9): {len(high_cves)}")
        
        # Show top recommendations
        if results['recommendations']:
            print(f"\n💡 Priority Recommendations:")
            for i, rec in enumerate(results['recommendations'][:5], 1):
                print(f"  {i}. [{rec['priority']}] {rec['title']}")
                print(f"     {rec['description']}")
                print(f"     Effort: {rec['estimated_effort']}")
        
        # Show scan performance
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            factors = risk_assessment.get('risk_factors', {})
            print(f"\n📋 Scan Statistics:")
            print(f"  CVE lookups performed: {factors.get('cve_scores_used', 0)}")
            print(f"  Recent CVEs found: {factors.get('recent_cves', 0)}")
            print(f"  High exploitability CVEs: {factors.get('high_exploitability', 0)}")
        
        print("\n" + "=" * 60)
        print("✅ Enhanced Security Scan Complete")
        print("=" * 60)
    
    # Uncomment to test
    asyncio.run(main())