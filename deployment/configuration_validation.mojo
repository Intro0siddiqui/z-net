# =============================================================================
# CONFIGURATION VALIDATION AND DRIFT DETECTION - PRODUCTION GRADE IMPLEMENTATION
# =============================================================================
# Comprehensive configuration validation with schema validation, environment
# consistency checks, drift detection, and automated remediation for production
# environments.
# =============================================================================

import json
import yaml
import jsonschema
import hashlib
import time
import os
import glob
import logging
import asyncio
import aiofiles
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import difflib
import re

# =============================================================================
# CONFIGURATION TYPES AND ENUMS
# =============================================================================

class ValidationSeverity(Enum):
    """Severity levels for configuration validation errors"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    ERROR = "error"

class DriftStatus(Enum):
    """Configuration drift status enumeration"""
    IN_SYNC = "in_sync"
    DRIFTED = "drifted"
    UNKNOWN = "unknown"
    VALIDATING = "validating"

class ValidationRuleType(Enum):
    """Types of validation rules"""
    SCHEMA_VALIDATION = "schema_validation"
    REFERENCE_VALIDATION = "reference_validation"
    ENVIRONMENT_CONSISTENCY = "environment_consistency"
    SECURITY_VALIDATION = "security_validation"
    PERFORMANCE_VALIDATION = "performance_validation"
    DEPENDENCY_VALIDATION = "dependency_validation"

class ConfigFormat(Enum):
    """Supported configuration file formats"""
    JSON = "json"
    YAML = "yaml"
    TOML = "toml"
    ENV = "env"
    XML = "xml"

@dataclass
class ValidationRule:
    """Configuration validation rule"""
    name: str
    rule_type: ValidationRuleType
    description: str
    schema: Optional[Dict[str, Any]] = None
    validation_function: Optional[callable] = None
    severity: ValidationSeverity = ValidationSeverity.ERROR
    enabled: bool = True
    auto_fix: bool = False
    fix_function: Optional[callable] = None
    tags: List[str] = field(default_factory=list)

@dataclass
class ConfigurationFile:
    """Configuration file representation"""
    path: str
    format: ConfigFormat
    content: str
    hash: str
    last_modified: datetime
    environment: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ValidationResult:
    """Result of configuration validation"""
    file_path: str
    rule_name: str
    is_valid: bool
    severity: ValidationSeverity
    message: str
    details: Dict[str, Any]
    line_number: Optional[int] = None
    suggested_fix: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class DriftDetectionResult:
    """Configuration drift detection result"""
    file_path: str
    current_hash: str
    reference_hash: str
    status: DriftStatus
    last_check: datetime
    changes: List[Dict[str, Any]]
    drift_percentage: float

@dataclass
class EnvironmentConfig:
    """Environment-specific configuration"""
    name: str
    description: str
    config_files: List[ConfigurationFile]
    validation_rules: List[ValidationRule]
    reference_configs: Dict[str, ConfigurationFile]
    dependencies: List[str]
    allowed_drifts: List[str]

@dataclass
class ConfigComparison:
    """Configuration comparison result"""
    file1: str
    file2: str
    differences: List[Dict[str, Any]]
    similarity_score: float
    significant_changes: List[Dict[str, Any]]
    ignored_changes: List[str]

# =============================================================================
# CONFIGURATION VALIDATOR
# =============================================================================

class ConfigurationValidator:
    """Comprehensive configuration validation and drift detection system"""
    
    def __init__(self, config_dir: str = "config", environments: List[str] = None):
        self.config_dir = Path(config_dir)
        self.environments = environments or ["development", "staging", "production"]
        self.logger = logging.getLogger(__name__)
        self.validation_rules: Dict[str, ValidationRule] = {}
        self.environment_configs: Dict[str, EnvironmentConfig] = {}
        self.drift_history: Dict[str, List[DriftDetectionResult]] = {}
        
        # Initialize validation rules
        self._setup_validation_rules()
        
        # Load environment configurations
        self._load_environment_configs()
    
    def _setup_validation_rules(self) -> None:
        """Setup default validation rules"""
        
        # Basic schema validation rule
        schema_rule = ValidationRule(
            name="json_schema_validation",
            rule_type=ValidationRuleType.SCHEMA_VALIDATION,
            description="Validate JSON schema compliance",
            severity=ValidationSeverity.ERROR,
            enabled=True,
            validation_function=self._validate_json_schema
        )
        self.validation_rules[schema_rule.name] = schema_rule
        
        # Environment consistency validation rule
        consistency_rule = ValidationRule(
            name="environment_consistency",
            rule_type=ValidationRuleType.ENVIRONMENT_CONSISTENCY,
            description="Check environment configuration consistency",
            severity=ValidationSeverity.WARNING,
            enabled=True,
            validation_function=self._validate_environment_consistency
        )
        self.validation_rules[consistency_rule.name] = consistency_rule
        
        # Security validation rule
        security_rule = ValidationRule(
            name="security_validation",
            rule_type=ValidationRuleType.SECURITY_VALIDATION,
            description="Validate security-related configurations",
            severity=ValidationSeverity.CRITICAL,
            enabled=True,
            validation_function=self._validate_security_config,
            auto_fix=True,
            fix_function=self._fix_security_config
        )
        self.validation_rules[security_rule.name] = security_rule
        
        # Reference validation rule
        reference_rule = ValidationRule(
            name="reference_validation",
            rule_type=ValidationRuleType.REFERENCE_VALIDATION,
            description="Validate against reference configurations",
            severity=ValidationSeverity.WARNING,
            enabled=True,
            validation_function=self._validate_against_reference
        )
        self.validation_rules[reference_rule.name] = reference_rule
        
        self.logger.info(f"Setup {len(self.validation_rules)} validation rules")
    
    def _load_environment_configs(self) -> None:
        """Load configuration files for each environment"""
        for env_name in self.environments:
            env_path = self.config_dir / env_name
            if not env_path.exists():
                self.logger.warning(f"Environment directory not found: {env_path}")
                continue
            
            try:
                config_files = self._discover_config_files(env_path)
                env_config = EnvironmentConfig(
                    name=env_name,
                    description=f"Configuration for {env_name} environment",
                    config_files=config_files,
                    validation_rules=[],
                    reference_configs={},
                    dependencies=[],
                    allowed_drifts=[]
                )
                
                self.environment_configs[env_name] = env_config
                self.logger.info(f"Loaded {len(config_files)} config files for {env_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to load environment {env_name}: {e}")
    
    def _discover_config_files(self, env_path: Path) -> List[ConfigurationFile]:
        """Discover all configuration files in environment directory"""
        config_files = []
        
        # Supported file patterns
        patterns = ["*.json", "*.yaml", "*.yml", "*.toml", "*.env", "*.xml"]
        
        for pattern in patterns:
            for file_path in env_path.rglob(pattern):
                if file_path.is_file():
                    try:
                        config_file = self._load_config_file(file_path)
                        config_files.append(config_file)
                    except Exception as e:
                        self.logger.error(f"Failed to load config file {file_path}: {e}")
        
        return config_files
    
    def _load_config_file(self, file_path: Path) -> ConfigurationFile:
        """Load a configuration file"""
        content = file_path.read_text()
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        stat = file_path.stat()
        
        # Determine file format
        format_map = {
            ".json": ConfigFormat.JSON,
            ".yaml": ConfigFormat.YAML,
            ".yml": ConfigFormat.YAML,
            ".toml": ConfigFormat.TOML,
            ".env": ConfigFormat.ENV,
            ".xml": ConfigFormat.XML,
        }
        
        format_type = format_map.get(file_path.suffix.lower(), ConfigFormat.JSON)
        
        return ConfigurationFile(
            path=str(file_path),
            format=format_type,
            content=content,
            hash=file_hash,
            last_modified=datetime.fromtimestamp(stat.st_mtime),
            environment=file_path.parent.name if len(file_path.parts) > 1 else None,
            service=file_path.stem,
            version="1.0"
        )
    
    async def validate_all_configurations(self) -> Dict[str, List[ValidationResult]]:
        """Validate all configurations across all environments"""
        all_results = {}
        
        for env_name, env_config in self.environment_configs.items():
            self.logger.info(f"Validating environment: {env_name}")
            results = await self.validate_environment(env_name)
            all_results[env_name] = results
        
        return all_results
    
    async def validate_environment(self, environment: str) -> List[ValidationResult]:
        """Validate all configurations in a specific environment"""
        if environment not in self.environment_configs:
            raise ValueError(f"Environment {environment} not found")
        
        env_config = self.environment_configs[environment]
        all_results = []
        
        # Run validations in parallel
        tasks = []
        for config_file in env_config.config_files:
            task = asyncio.create_task(self.validate_config_file(config_file, env_config))
            tasks.append(task)
        
        file_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(file_results):
            if isinstance(result, Exception):
                self.logger.error(f"Validation failed for {env_config.config_files[i].path}: {result}")
                error_result = ValidationResult(
                    file_path=env_config.config_files[i].path,
                    rule_name="validation_execution",
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Validation execution failed: {result}",
                    details={},
                    timestamp=datetime.now()
                )
                all_results.append(error_result)
            else:
                all_results.extend(result)
        
        return all_results
    
    async def validate_config_file(self, config_file: ConfigurationFile, env_config: EnvironmentConfig) -> List[ValidationResult]:
        """Validate a single configuration file"""
        results = []
        
        # Apply all validation rules
        for rule_name, rule in self.validation_rules.items():
            if not rule.enabled:
                continue
            
            try:
                if rule.validation_function:
                    result = await rule.validation_function(config_file, env_config, rule)
                    if result:
                        results.append(result)
            except Exception as e:
                self.logger.error(f"Validation rule {rule_name} failed for {config_file.path}: {e}")
                error_result = ValidationResult(
                    file_path=config_file.path,
                    rule_name=rule_name,
                    is_valid=False,
                    severity=ValidationSeverity.ERROR,
                    message=f"Validation rule execution failed: {e}",
                    details={}
                )
                results.append(error_result)
        
        return results
    
    async def detect_configuration_drift(self, environment: str) -> Dict[str, DriftDetectionResult]:
        """Detect configuration drift for an environment"""
        if environment not in self.environment_configs:
            raise ValueError(f"Environment {environment} not found")
        
        env_config = self.environment_configs[environment]
        drift_results = {}
        
        for config_file in env_config.config_files:
            try:
                # Load current version
                current_file = self._load_config_file(Path(config_file.path))
                
                # Get reference version if available
                reference_file = None
                if config_file.service in env_config.reference_configs:
                    reference_file = env_config.reference_configs[config_file.service]
                
                # Detect drift
                drift_result = await self._detect_file_drift(current_file, reference_file, env_config)
                drift_results[config_file.path] = drift_result
                
                # Update history
                if environment not in self.drift_history:
                    self.drift_history[environment] = []
                self.drift_history[environment].append(drift_result)
                
            except Exception as e:
                self.logger.error(f"Drift detection failed for {config_file.path}: {e}")
        
        return drift_results
    
    async def _detect_file_drift(self, current: ConfigurationFile, reference: Optional[ConfigurationFile], env_config: EnvironmentConfig) -> DriftDetectionResult:
        """Detect drift for a single configuration file"""
        status = DriftStatus.VALIDATING
        
        if reference is None:
            # No reference available
            return DriftDetectionResult(
                file_path=current.path,
                current_hash=current.hash,
                reference_hash="",
                status=DriftStatus.UNKNOWN,
                last_check=datetime.now(),
                changes=[],
                drift_percentage=0.0
            )
        
        # Calculate drift
        changes = []
        drift_percentage = 0.0
        
        if current.hash != reference.hash:
            status = DriftStatus.DRIFTED
            changes = await self._calculate_config_differences(current, reference)
            drift_percentage = len(changes) / max(len(current.content), 1) * 100
        else:
            status = DriftStatus.IN_SYNC
        
        # Check if drift is allowed
        for allowed_drift in env_config.allowed_drifts:
            if allowed_drift in current.path:
                status = DriftStatus.IN_SYNC
                break
        
        return DriftDetectionResult(
            file_path=current.path,
            current_hash=current.hash,
            reference_hash=reference.hash,
            status=status,
            last_check=datetime.now(),
            changes=changes,
            drift_percentage=drift_percentage
        )
    
    async def _calculate_config_differences(self, current: ConfigurationFile, reference: ConfigurationFile) -> List[Dict[str, Any]]:
        """Calculate differences between current and reference configurations"""
        differences = []
        
        try:
            # Parse both configurations
            current_data = self._parse_config_content(current.content, current.format)
            reference_data = self._parse_config_content(reference.content, reference.format)
            
            # Calculate differences recursively
            differences = self._recursive_diff(reference_data, current_data, "")
            
        except Exception as e:
            self.logger.error(f"Failed to calculate config differences: {e}")
        
        return differences
    
    def _parse_config_content(self, content: str, format_type: ConfigFormat) -> Any:
        """Parse configuration content based on format"""
        if format_type == ConfigFormat.JSON:
            return json.loads(content)
        elif format_type == ConfigFormat.YAML:
            return yaml.safe_load(content)
        elif format_type == ConfigFormat.TOML:
            import toml
            return toml.loads(content)
        else:
            # For other formats, return as string
            return {"content": content}
    
    def _recursive_diff(self, reference: Any, current: Any, path: str) -> List[Dict[str, Any]]:
        """Recursively calculate differences between two configurations"""
        differences = []
        
        if isinstance(reference, dict) and isinstance(current, dict):
            # Dictionary comparison
            all_keys = set(reference.keys()) | set(current.keys())
            
            for key in all_keys:
                current_path = f"{path}.{key}" if path else key
                
                if key not in reference:
                    differences.append({
                        "type": "added",
                        "path": current_path,
                        "value": current[key],
                        "description": f"Key '{key}' was added"
                    })
                elif key not in current:
                    differences.append({
                        "type": "removed",
                        "path": current_path,
                        "value": reference[key],
                        "description": f"Key '{key}' was removed"
                    })
                else:
                    # Recursively check nested structure
                    sub_differences = self._recursive_diff(reference[key], current[key], current_path)
                    differences.extend(sub_differences)
        
        elif isinstance(reference, list) and isinstance(current, list):
            # List comparison
            max_len = max(len(reference), len(current))
            
            for i in range(max_len):
                current_path = f"{path}[{i}]"
                
                if i >= len(reference):
                    differences.append({
                        "type": "added",
                        "path": current_path,
                        "value": current[i],
                        "description": f"Item at index {i} was added"
                    })
                elif i >= len(current):
                    differences.append({
                        "type": "removed",
                        "path": current_path,
                        "value": reference[i],
                        "description": f"Item at index {i} was removed"
                    })
                else:
                    # Recursively check list items
                    sub_differences = self._recursive_diff(reference[i], current[i], current_path)
                    differences.extend(sub_differences)
        
        else:
            # Primitive value comparison
            if reference != current:
                differences.append({
                    "type": "modified",
                    "path": path,
                    "reference_value": reference,
                    "current_value": current,
                    "description": f"Value changed from {reference} to {current}"
                })
        
        return differences
    
    async def compare_environments(self, env1: str, env2: str) -> Dict[str, ConfigComparison]:
        """Compare configurations between two environments"""
        if env1 not in self.environment_configs or env2 not in self.environment_configs:
            raise ValueError(f"Environment not found: {env1} or {env2}")
        
        config1 = self.environment_configs[env1]
        config2 = self.environment_configs[env2]
        
        comparisons = {}
        
        # Create mapping of service names to config files
        service_files1 = {cf.service: cf for cf in config1.config_files if cf.service}
        service_files2 = {cf.service: cf for cf in config2.config_files if cf.service}
        
        all_services = set(service_files1.keys()) | set(service_files2.keys())
        
        for service in all_services:
            file1 = service_files1.get(service)
            file2 = service_files2.get(service)
            
            if file1 and file2:
                comparison = await self._compare_config_files(file1, file2)
                comparisons[service] = comparison
            elif file1:
                comparison = ConfigComparison(
                    file1=file1.path,
                    file2="",
                    differences=[{"type": "missing_in_env2", "description": f"Service {service} missing in {env2}"}],
                    similarity_score=0.0,
                    significant_changes=[],
                    ignored_changes=[]
                )
                comparisons[service] = comparison
            elif file2:
                comparison = ConfigComparison(
                    file1="",
                    file2=file2.path,
                    differences=[{"type": "missing_in_env1", "description": f"Service {service} missing in {env1}"}],
                    similarity_score=0.0,
                    significant_changes=[],
                    ignored_changes=[]
                )
                comparisons[service] = comparison
        
        return comparisons
    
    async def _compare_config_files(self, file1: ConfigurationFile, file2: ConfigurationFile) -> ConfigComparison:
        """Compare two configuration files"""
        differences = await self._calculate_config_differences(file1, file2)
        
        # Calculate similarity score
        similarity_score = self._calculate_similarity_score(file1.content, file2.content)
        
        # Filter significant changes (non-comments, non-whitespace)
        significant_changes = []
        ignored_changes = []
        
        for diff in differences:
            if self._is_significant_change(diff):
                significant_changes.append(diff)
            else:
                ignored_changes.append(diff.get("path", "unknown"))
        
        return ConfigComparison(
            file1=file1.path,
            file2=file2.path,
            differences=differences,
            similarity_score=similarity_score,
            significant_changes=significant_changes,
            ignored_changes=ignored_changes
        )
    
    def _calculate_similarity_score(self, content1: str, content2: str) -> float:
        """Calculate similarity score between two configuration contents"""
        similarity = difflib.SequenceMatcher(None, content1, content2)
        return similarity.ratio()
    
    def _is_significant_change(self, change: Dict[str, Any]) -> bool:
        """Determine if a change is significant"""
        change_type = change.get("type", "")
        path = change.get("path", "")
        
        # Ignore comment-like changes
        if path.startswith("#") or path.startswith("//"):
            return False
        
        # Ignore whitespace-only changes
        if change_type == "modified":
            ref_val = str(change.get("reference_value", ""))
            curr_val = str(change.get("current_value", ""))
            if ref_val.strip() == "" and curr_val.strip() == "":
                return False
        
        return True
    
    def generate_validation_report(self, results: Dict[str, List[ValidationResult]]) -> Dict[str, Any]:
        """Generate a comprehensive validation report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "environments": {},
            "summary": {
                "total_files": 0,
                "valid_files": 0,
                "invalid_files": 0,
                "critical_issues": 0,
                "warnings": 0
            }
        }
        
        for env_name, env_results in results.items():
            env_summary = {
                "total_files": len(set(r.file_path for r in env_results)),
                "valid_files": len([r for r in env_results if r.is_valid]),
                "invalid_files": len([r for r in env_results if not r.is_valid]),
                "issues": {
                    "critical": len([r for r in env_results if r.severity == ValidationSeverity.CRITICAL]),
                    "errors": len([r for r in env_results if r.severity == ValidationSeverity.ERROR]),
                    "warnings": len([r for r in env_results if r.severity == ValidationSeverity.WARNING]),
                },
                "details": [r.__dict__ for r in env_results]
            }
            
            report["environments"][env_name] = env_summary
            
            # Update global summary
            report["summary"]["total_files"] += env_summary["total_files"]
            report["summary"]["valid_files"] += env_summary["valid_files"]
            report["summary"]["invalid_files"] += env_summary["invalid_files"]
            report["summary"]["critical_issues"] += env_summary["issues"]["critical"]
            report["summary"]["warnings"] += env_summary["issues"]["warnings"]
        
        return report
    
    # =============================================================================
    # VALIDATION RULE IMPLEMENTATIONS
    # =============================================================================
    
    async def _validate_json_schema(self, config_file: ConfigurationFile, env_config: EnvironmentConfig, rule: ValidationRule) -> Optional[ValidationResult]:
        """Validate JSON/YAML schema"""
        try:
            if config_file.format == ConfigFormat.JSON:
                data = json.loads(config_file.content)
            elif config_file.format == ConfigFormat.YAML:
                data = yaml.safe_load(config_file.content)
            else:
                return None  # Skip non-JSON/YAML files
            
            if rule.schema:
                jsonschema.validate(data, rule.schema)
            
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=True,
                severity=rule.severity,
                message="Schema validation passed",
                details={}
            )
            
        except jsonschema.ValidationError as e:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=False,
                severity=rule.severity,
                message=f"Schema validation failed: {e.message}",
                details={"schema_error": str(e)},
                line_number=e.lineno if hasattr(e, 'lineno') else None
            )
        except Exception as e:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=False,
                severity=rule.severity,
                message=f"Failed to parse configuration: {e}",
                details={"parse_error": str(e)}
            )
    
    async def _validate_environment_consistency(self, config_file: ConfigurationFile, env_config: EnvironmentConfig, rule: ValidationRule) -> Optional[ValidationResult]:
        """Validate environment consistency"""
        # Check for environment-specific patterns
        environment_patterns = {
            "development": ["localhost", "dev.", "test."],
            "staging": ["staging.", "stage."],
            "production": ["prod.", "production."]
        }
        
        patterns = environment_patterns.get(env_config.name, [])
        issues = []
        
        for pattern in patterns:
            if pattern in config_file.content.lower():
                issues.append(f"Found environment-specific pattern '{pattern}'")
        
        if issues:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=False,
                severity=rule.severity,
                message=f"Environment consistency issues: {'; '.join(issues)}",
                details={"issues": issues}
            )
        
        return ValidationResult(
            file_path=config_file.path,
            rule_name=rule.name,
            is_valid=True,
            severity=rule.severity,
            message="Environment consistency check passed",
            details={}
        )
    
    async def _validate_security_config(self, config_file: ConfigurationFile, env_config: EnvironmentConfig, rule: ValidationRule) -> Optional[ValidationResult]:
        """Validate security-related configurations"""
        issues = []
        
        # Check for insecure patterns
        insecure_patterns = [
            (r"password\s*=\s*['\"][^'\"]+['\"]", "Password in configuration"),
            (r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", "API key in configuration"),
            (r"secret\s*=\s*['\"][^'\"]+['\"]", "Secret in configuration"),
            (r"debug\s*=\s*true", "Debug mode enabled in production"),
        ]
        
        for pattern, description in insecure_patterns:
            if re.search(pattern, config_file.content, re.IGNORECASE):
                issues.append(description)
        
        if issues:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=False,
                severity=rule.severity,
                message=f"Security issues found: {'; '.join(issues)}",
                details={"security_issues": issues}
            )
        
        return ValidationResult(
            file_path=config_file.path,
            rule_name=rule.name,
            is_valid=True,
            severity=rule.severity,
            message="Security validation passed",
            details={}
        )
    
    async def _validate_against_reference(self, config_file: ConfigurationFile, env_config: EnvironmentConfig, rule: ValidationRule) -> Optional[ValidationResult]:
        """Validate against reference configurations"""
        if config_file.service not in env_config.reference_configs:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=True,
                severity=rule.severity,
                message="No reference configuration available",
                details={}
            )
        
        reference = env_config.reference_configs[config_file.service]
        comparison = await self._compare_config_files(config_file, reference)
        
        if comparison.significant_changes:
            return ValidationResult(
                file_path=config_file.path,
                rule_name=rule.name,
                is_valid=False,
                severity=rule.severity,
                message=f"Significant differences from reference: {len(comparison.significant_changes)} changes",
                details={"significant_changes": comparison.significant_changes}
            )
        
        return ValidationResult(
            file_path=config_file.path,
            rule_name=rule.name,
            is_valid=True,
            severity=rule.severity,
            message="Reference validation passed",
            details={"similarity_score": comparison.similarity_score}
        )
    
    async def _fix_security_config(self, result: ValidationResult) -> Optional[str]:
        """Attempt to fix security configuration issues"""
        # This is a placeholder - actual implementation would depend on specific security issues
        fixed_content = None
        
        # Example: Remove obvious secrets (simplified)
        if "password" in result.message.lower():
            # This would need actual content to fix
            pass
        
        return fixed_content
    
    def add_validation_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule"""
        self.validation_rules[rule.name] = rule
        self.logger.info(f"Added validation rule: {rule.name}")
    
    def register_reference_config(self, environment: str, service: str, config_path: str) -> None:
        """Register a reference configuration for an environment"""
        if environment in self.environment_configs:
            try:
                reference_file = self._load_config_file(Path(config_path))
                self.environment_configs[environment].reference_configs[service] = reference_file
                self.logger.info(f"Registered reference config for {environment}/{service}")
            except Exception as e:
                self.logger.error(f"Failed to register reference config: {e}")

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

class ConfigurationMonitor:
    """Monitor configuration changes and drift"""
    
    def __init__(self, validator: ConfigurationValidator, check_interval: int = 300):
        self.validator = validator
        self.check_interval = check_interval
        self.logger = logging.getLogger(__name__)
        self.last_check_times: Dict[str, datetime] = {}
        self.drift_threshold = 0.1  # 10% drift threshold
    
    async def start_monitoring(self) -> None:
        """Start continuous monitoring of configurations"""
        self.logger.info("Starting configuration monitoring")
        
        while True:
            try:
                await self._check_all_environments()
                await asyncio.sleep(self.check_interval)
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.logger.error(f"Configuration monitoring error: {e}")
                await asyncio.sleep(60)  # Retry after 1 minute
    
    async def _check_all_environments(self) -> None:
        """Check all environments for drift and issues"""
        for env_name in self.validator.environments:
            try:
                # Check drift
                drift_results = await self.validator.detect_configuration_drift(env_name)
                
                # Check for significant drift
                drifted_files = [path for path, result in drift_results.items() 
                               if result.status == DriftStatus.DRIFTED and 
                               result.drift_percentage > self.drift_threshold]
                
                if drifted_files:
                    await self._alert_drift_detected(env_name, drifted_files)
                
                # Update last check time
                self.last_check_times[env_name] = datetime.now()
                
            except Exception as e:
                self.logger.error(f"Failed to check environment {env_name}: {e}")
    
    async def _alert_drift_detected(self, environment: str, drifted_files: List[str]) -> None:
        """Alert when configuration drift is detected"""
        self.logger.warning(f"Configuration drift detected in {environment}: {', '.join(drifted_files)}")
        
        # In a real implementation, this would send alerts via:
        # - Email notifications
        # - Slack/webhook notifications
        # - PagerDuty alerts
        # - Monitoring system integration
    
    def get_drift_history(self, environment: str) -> List[DriftDetectionResult]:
        """Get drift detection history for an environment"""
        return self.validator.drift_history.get(environment, [])
    
    def export_validation_report(self, output_path: str, format_type: str = "json") -> None:
        """Export validation report to file"""
        # Get latest validation results (this would need to be stored)
        report_data = {"timestamp": datetime.now().isoformat(), "message": "Report export not implemented"}
        
        if format_type.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
        elif format_type.lower() == "yaml":
            with open(output_path, 'w') as f:
                yaml.dump(report_data, f)

# =============================================================================
# MAIN APPLICATION
# =============================================================================

async def main():
    """Main application entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize configuration validator
    validator = ConfigurationValidator("config")
    
    # Run validation
    results = await validator.validate_all_configurations()
    
    # Generate report
    report = validator.generate_validation_report(results)
    
    print("Configuration Validation Report")
    print("=" * 50)
    print(json.dumps(report, indent=2, default=str))
    
    # Start monitoring (if desired)
    monitor = ConfigurationMonitor(validator)
    await monitor.start_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
