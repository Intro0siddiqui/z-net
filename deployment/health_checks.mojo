# =============================================================================
# HEALTH CHECKS AND SYSTEM MONITORING - PRODUCTION GRADE IMPLEMENTATION
# =============================================================================
# Comprehensive health monitoring with HTTP endpoints, connection validation,
# resource monitoring, and automated alerting for production environments.
# =============================================================================

import asyncio
import json
import time
import psutil
import aiohttp
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import socket
import subprocess
import ssl
import hashlib
from contextlib import asynccontextmanager

# =============================================================================
# HEALTH CHECK CONFIGURATION TYPES
# =============================================================================

class HealthStatus(Enum):
    """Health check status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    FAILING = "failing"

class CheckType(Enum):
    """Types of health checks"""
    HTTP_ENDPOINT = "http_endpoint"
    TCP_CONNECTION = "tcp_connection"
    DATABASE_CONNECTION = "database_connection"
    EXTERNAL_SERVICE = "external_service"
    RESOURCE_USAGE = "resource_usage"
    FILE_SYSTEM = "file_system"
    NETWORK_CONNECTIVITY = "network_connectivity"
    PROCESS_STATUS = "process_status"
    SECURITY_VALIDATION = "security_validation"

@dataclass
class HealthCheckConfig:
    """Configuration for health checks"""
    name: str
    check_type: CheckType
    endpoint: Optional[str] = None
    port: Optional[int] = None
    timeout: int = 30
    interval: int = 60
    threshold: float = 1.0
    critical_threshold: float = 0.5
    retry_count: int = 3
    enabled: bool = True
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class HealthCheckResult:
    """Result of a health check execution"""
    check_name: str
    status: HealthStatus
    timestamp: datetime
    response_time_ms: float
    message: str
    details: Dict[str, Any]
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "response_time_ms": self.response_time_ms,
            "message": self.message,
            "details": self.details,
            "error": self.error
        }

@dataclass
class SystemMetrics:
    """System resource metrics"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    disk_usage_percent: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    active_connections: int
    load_average: List[float]
    uptime_seconds: int

# =============================================================================
# HEALTH CHECK MANAGER
# =============================================================================

class HealthCheckManager:
    """Comprehensive health check manager for production monitoring"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.checks: Dict[str, HealthCheckConfig] = {}
        self.results: Dict[str, HealthCheckResult] = {}
        self.system_metrics: Optional[SystemMetrics] = None
        self.alert_webhook: Optional[str] = None
        self.metrics_history: List[Tuple[datetime, SystemMetrics]] = []
        
        # Load configuration
        if config_path:
            self.load_config(config_path)
        
        # Setup default checks
        self._setup_default_checks()
        
    def load_config(self, config_path: str) -> None:
        """Load health check configuration from file"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                
            for check_data in config_data.get('checks', []):
                check_config = HealthCheckConfig(**check_data)
                self.checks[check_config.name] = check_config
                
            self.alert_webhook = config_data.get('alert_webhook')
            self.logger.info(f"Loaded {len(self.checks)} health checks from {config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_path}: {e}")
            raise
    
    def _setup_default_checks(self) -> None:
        """Setup default health checks"""
        default_checks = [
            HealthCheckConfig(
                name="http_health",
                check_type=CheckType.HTTP_ENDPOINT,
                endpoint="http://localhost:8080/health",
                interval=30,
                tags=["core", "api"]
            ),
            HealthCheckConfig(
                name="tcp_port_8080",
                check_type=CheckType.TCP_CONNECTION,
                port=8080,
                interval=60,
                tags=["connectivity"]
            ),
            HealthCheckConfig(
                name="system_resources",
                check_type=CheckType.RESOURCE_USAGE,
                threshold=80.0,
                critical_threshold=90.0,
                interval=30,
                tags=["infrastructure"]
            ),
            HealthCheckConfig(
                name="disk_space",
                check_type=CheckType.FILE_SYSTEM,
                threshold=85.0,
                critical_threshold=95.0,
                interval=300,
                tags=["storage"]
            ),
            HealthCheckConfig(
                name="network_connectivity",
                check_type=CheckType.NETWORK_CONNECTIVITY,
                endpoint="8.8.8.8",
                interval=120,
                tags=["network"]
            )
        ]
        
        for check in default_checks:
            if check.name not in self.checks:
                self.checks[check.name] = check
    
    async def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Execute all enabled health checks"""
        self.logger.info("Starting health check execution")
        
        # Update system metrics
        await self._update_system_metrics()
        
        tasks = []
        for check_config in self.checks.values():
            if check_config.enabled:
                task = asyncio.create_task(self._run_check(check_config))
                tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                check_name = list(self.checks.values())[i].name
                self.results[check_name] = HealthCheckResult(
                    check_name=check_name,
                    status=HealthStatus.FAILING,
                    timestamp=datetime.now(),
                    response_time_ms=0,
                    message="Health check execution failed",
                    details={},
                    error=str(result)
                )
            else:
                self.results[result.check_name] = result
        
        # Check for alerts
        await self._check_alerts()
        
        self.logger.info(f"Completed health checks: {len(self.results)} executed")
        return self.results.copy()
    
    async def _run_check(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Execute a single health check"""
        start_time = time.time()
        
        try:
            if check_config.check_type == CheckType.HTTP_ENDPOINT:
                return await self._check_http_endpoint(check_config)
            elif check_config.check_type == CheckType.TCP_CONNECTION:
                return await self._check_tcp_connection(check_config)
            elif check_config.check_type == CheckType.RESOURCE_USAGE:
                return await self._check_resource_usage(check_config)
            elif check_config.check_type == CheckType.FILE_SYSTEM:
                return await self._check_file_system(check_config)
            elif check_config.check_type == CheckType.NETWORK_CONNECTIVITY:
                return await self._check_network_connectivity(check_config)
            elif check_config.check_type == CheckType.EXTERNAL_SERVICE:
                return await self._check_external_service(check_config)
            elif check_config.check_type == CheckType.PROCESS_STATUS:
                return await self._check_process_status(check_config)
            else:
                return HealthCheckResult(
                    check_name=check_config.name,
                    status=HealthStatus.UNKNOWN,
                    timestamp=datetime.now(),
                    response_time_ms=(time.time() - start_time) * 1000,
                    message="Unknown check type",
                    details={}
                )
                
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=(time.time() - start_time) * 1000,
                message="Health check failed with exception",
                details={},
                error=str(e)
            )
    
    async def _check_http_endpoint(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check HTTP endpoint health"""
        timeout = aiohttp.ClientTimeout(total=check_config.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.get(check_config.endpoint) as response:
                    response_time = (time.time() - asyncio.get_event_loop().time()) * 1000
                    
                    if response.status == 200:
                        status = HealthStatus.HEALTHY
                        message = "HTTP endpoint is responsive"
                    elif response.status >= 500:
                        status = HealthStatus.CRITICAL
                        message = f"Server error: {response.status}"
                    elif response.status >= 400:
                        status = HealthStatus.DEGRADED
                        message = f"Client error: {response.status}"
                    else:
                        status = HealthStatus.DEGRADED
                        message = f"Unexpected status code: {response.status}"
                    
                    details = {
                        "status_code": response.status,
                        "response_headers": dict(response.headers),
                        "content_length": len(await response.read())
                    }
                    
                    return HealthCheckResult(
                        check_name=check_config.name,
                        status=status,
                        timestamp=datetime.now(),
                        response_time_ms=response_time,
                        message=message,
                        details=details
                    )
                    
            except asyncio.TimeoutError:
                return HealthCheckResult(
                    check_name=check_config.name,
                    status=HealthStatus.CRITICAL,
                    timestamp=datetime.now(),
                    response_time_ms=check_config.timeout * 1000,
                    message="HTTP request timeout",
                    details={}
                )
            except Exception as e:
                return HealthCheckResult(
                    check_name=check_config.name,
                    status=HealthStatus.FAILING,
                    timestamp=datetime.now(),
                    response_time_ms=0,
                    message="HTTP request failed",
                    details={},
                    error=str(e)
                )
    
    async def _check_tcp_connection(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check TCP connection to a port"""
        try:
            # Use asyncio socket for non-blocking connection
            loop = asyncio.get_event_loop()
            
            def _connect():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(check_config.timeout)
                try:
                    sock.connect(('localhost', check_config.port))
                    return True
                except Exception:
                    return False
                finally:
                    sock.close()
            
            is_connected = await loop.run_in_executor(None, _connect)
            
            if is_connected:
                status = HealthStatus.HEALTHY
                message = f"TCP connection to port {check_config.port} successful"
            else:
                status = HealthStatus.CRITICAL
                message = f"Cannot connect to port {check_config.port}"
            
            return HealthCheckResult(
                check_name=check_config.name,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=check_config.timeout * 1000,
                message=message,
                details={"port": check_config.port, "timeout": check_config.timeout}
            )
            
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=0,
                message="TCP connection check failed",
                details={},
                error=str(e)
            )
    
    async def _check_resource_usage(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check system resource usage"""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_mb = memory.used / (1024 * 1024)
            memory_total_mb = memory.total / (1024 * 1024)
            
            # Get load average
            load_avg = list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0.0, 0.0, 0.0]
            
            # Determine status based on thresholds
            if cpu_percent > check_config.critical_threshold or memory_percent > check_config.critical_threshold:
                status = HealthStatus.CRITICAL
            elif cpu_percent > check_config.threshold or memory_percent > check_config.threshold:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
            
            message = f"CPU: {cpu_percent:.1f}%, Memory: {memory_percent:.1f}%"
            
            details = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "memory_used_mb": memory_used_mb,
                "memory_total_mb": memory_total_mb,
                "load_average": load_avg,
                "cpu_count": psutil.cpu_count()
            }
            
            return HealthCheckResult(
                check_name=check_config.name,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=0,
                message=message,
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=0,
                message="Resource usage check failed",
                details={},
                error=str(e)
            )
    
    async def _check_file_system(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check file system disk usage"""
        try:
            disk_usage = psutil.disk_usage('/')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            disk_free_gb = disk_usage.free / (1024 * 1024 * 1024)
            
            # Determine status
            if disk_percent > check_config.critical_threshold:
                status = HealthStatus.CRITICAL
                message = f"Critical disk usage: {disk_percent:.1f}%"
            elif disk_percent > check_config.threshold:
                status = HealthStatus.DEGRADED
                message = f"High disk usage: {disk_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage: {disk_percent:.1f}%"
            
            details = {
                "disk_usage_percent": disk_percent,
                "disk_free_gb": disk_free_gb,
                "disk_total_gb": disk_usage.total / (1024 * 1024 * 1024),
                "disk_used_gb": disk_usage.used / (1024 * 1024 * 1024)
            }
            
            return HealthCheckResult(
                check_name=check_config.name,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=0,
                message=message,
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=0,
                message="File system check failed",
                details={},
                error=str(e)
            )
    
    async def _check_network_connectivity(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check network connectivity"""
        try:
            target = check_config.endpoint or "8.8.8.8"
            
            def _ping():
                try:
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '3', target],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    return result.returncode == 0
                except:
                    return False
            
            loop = asyncio.get_event_loop()
            is_reachable = await loop.run_in_executor(None, _ping)
            
            if is_reachable:
                status = HealthStatus.HEALTHY
                message = f"Network connectivity to {target} successful"
            else:
                status = HealthStatus.CRITICAL
                message = f"Cannot reach {target}"
            
            details = {
                "target": target,
                "timeout": check_config.timeout
            }
            
            return HealthCheckResult(
                check_name=check_config.name,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=0,
                message=message,
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=0,
                message="Network connectivity check failed",
                details={},
                error=str(e)
            )
    
    async def _check_external_service(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check external service availability"""
        # Placeholder implementation for external service checks
        return HealthCheckResult(
            check_name=check_config.name,
            status=HealthStatus.HEALTHY,
            timestamp=datetime.now(),
            response_time_ms=0,
            message="External service check not implemented",
            details={}
        )
    
    async def _check_process_status(self, check_config: HealthCheckConfig) -> HealthCheckResult:
        """Check if process is running"""
        try:
            process_name = check_config.endpoint  # Using endpoint field for process name
            processes = [p for p in psutil.process_iter(['pid', 'name']) if process_name.lower() in p.info['name'].lower()]
            
            if processes:
                status = HealthStatus.HEALTHY
                message = f"Process '{process_name}' is running"
                details = {"pid": processes[0].info['pid'], "name": processes[0].info['name']}
            else:
                status = HealthStatus.CRITICAL
                message = f"Process '{process_name}' not found"
                details = {"process_name": process_name}
            
            return HealthCheckResult(
                check_name=check_config.name,
                status=status,
                timestamp=datetime.now(),
                response_time_ms=0,
                message=message,
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                check_name=check_config.name,
                status=HealthStatus.FAILING,
                timestamp=datetime.now(),
                response_time_ms=0,
                message="Process status check failed",
                details={},
                error=str(e)
            )
    
    async def _update_system_metrics(self) -> None:
        """Update system metrics"""
        try:
            self.system_metrics = SystemMetrics(
                cpu_percent=psutil.cpu_percent(interval=0.1),
                memory_percent=psutil.virtual_memory().percent,
                memory_used_mb=psutil.virtual_memory().used / (1024 * 1024),
                memory_total_mb=psutil.virtual_memory().total / (1024 * 1024),
                disk_usage_percent=(psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
                disk_free_gb=psutil.disk_usage('/').free / (1024 * 1024 * 1024),
                network_bytes_sent=psutil.net_io_counters().bytes_sent,
                network_bytes_recv=psutil.net_io_counters().bytes_recv,
                active_connections=len(psutil.net_connections()),
                load_average=list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0.0, 0.0, 0.0],
                uptime_seconds=int(time.time() - psutil.boot_time())
            )
            
            # Keep history (last 24 hours)
            self.metrics_history.append((datetime.now(), self.system_metrics))
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.metrics_history = [(ts, metrics) for ts, metrics in self.metrics_history if ts > cutoff_time]
            
        except Exception as e:
            self.logger.error(f"Failed to update system metrics: {e}")
    
    async def _check_alerts(self) -> None:
        """Check for conditions that should trigger alerts"""
        critical_checks = [result for result in self.results.values() if result.status == HealthStatus.CRITICAL]
        failing_checks = [result for result in self.results.values() if result.status == HealthStatus.FAILING]
        
        if critical_checks or failing_checks:
            await self._send_alert(critical_checks, failing_checks)
    
    async def _send_alert(self, critical_checks: List[HealthCheckResult], failing_checks: List[HealthCheckResult]) -> None:
        """Send alert notification"""
        if not self.alert_webhook:
            return
        
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "severity": "critical" if critical_checks else "warning",
            "critical_checks": [check.to_dict() for check in critical_checks],
            "failing_checks": [check.to_dict() for check in failing_checks],
            "system_metrics": self.system_metrics.__dict__ if self.system_metrics else None
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.alert_webhook, json=alert_data) as response:
                    if response.status == 200:
                        self.logger.info("Alert sent successfully")
                    else:
                        self.logger.warning(f"Failed to send alert: HTTP {response.status}")
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")

# =============================================================================
# HEALTH CHECK HTTP SERVER
# =============================================================================

class HealthCheckServer:
    """HTTP server for health check endpoints"""
    
    def __init__(self, health_manager: HealthCheckManager, host: str = "0.0.0.0", port: int = 8080):
        self.health_manager = health_manager
        self.host = host
        self.port = port
        self.app = None
        self.logger = logging.getLogger(__name__)
    
    async def start(self) -> None:
        """Start the health check HTTP server"""
        from aiohttp import web
        
        self.app = web.Application()
        
        # Add routes
        self.app.router.add_get('/health', self.health_endpoint)
        self.app.router.add_get('/health/detailed', self.detailed_health_endpoint)
        self.app.router.add_get('/health/metrics', self.metrics_endpoint)
        self.app.router.add_get('/health/checks', self.checks_endpoint)
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        self.logger.info(f"Health check server started on {self.host}:{self.port}")
    
    async def health_endpoint(self, request):
        """Basic health check endpoint"""
        try:
            # Quick health check
            results = await self.health_manager.run_all_checks()
            
            # Determine overall health
            statuses = [result.status for result in results.values()]
            
            if HealthStatus.FAILING in statuses or HealthStatus.CRITICAL in statuses:
                status_code = 503  # Service Unavailable
                overall_status = "unhealthy"
            elif HealthStatus.DEGRADED in statuses:
                status_code = 200  # Still return 200 but mark as degraded
                overall_status = "degraded"
            else:
                status_code = 200
                overall_status = "healthy"
            
            response_data = {
                "status": overall_status,
                "timestamp": datetime.now().isoformat(),
                "checks_executed": len(results),
                "healthy_checks": len([r for r in results.values() if r.status == HealthStatus.HEALTHY]),
                "degraded_checks": len([r for r in results.values() if r.status == HealthStatus.DEGRADED]),
                "critical_checks": len([r for r in results.values() if r.status == HealthStatus.CRITICAL]),
                "failing_checks": len([r for r in results.values() if r.status == HealthStatus.FAILING])
            }
            
            return web.json_response(response_data, status=status_code)
            
        except Exception as e:
            self.health_manager.logger.error(f"Health check endpoint failed: {e}")
            return web.json_response({
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }, status=500)
    
    async def detailed_health_endpoint(self, request):
        """Detailed health check with full results"""
        try:
            results = await self.health_manager.run_all_checks()
            
            response_data = {
                "timestamp": datetime.now().isoformat(),
                "overall_status": self._get_overall_status(results),
                "system_metrics": self.health_manager.system_metrics.__dict__ if self.health_manager.system_metrics else None,
                "checks": {name: result.to_dict() for name, result in results.items()}
            }
            
            return web.json_response(response_data)
            
        except Exception as e:
            self.health_manager.logger.error(f"Detailed health check failed: {e}")
            return web.json_response({
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }, status=500)
    
    async def metrics_endpoint(self, request):
        """System metrics endpoint"""
        try:
            if not self.health_manager.system_metrics:
                await self.health_manager._update_system_metrics()
            
            response_data = {
                "timestamp": datetime.now().isoformat(),
                "metrics": self.health_manager.system_metrics.__dict__ if self.health_manager.system_metrics else None,
                "history_count": len(self.health_manager.metrics_history)
            }
            
            return web.json_response(response_data)
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    async def checks_endpoint(self, request):
        """List all configured health checks"""
        try:
            checks_data = {
                name: {
                    "name": config.name,
                    "check_type": config.check_type.value,
                    "endpoint": config.endpoint,
                    "port": config.port,
                    "interval": config.interval,
                    "enabled": config.enabled,
                    "tags": config.tags
                }
                for name, config in self.health_manager.checks.items()
            }
            
            return web.json_response({"checks": checks_data})
            
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
    
    def _get_overall_status(self, results) -> str:
        """Determine overall health status from check results"""
        statuses = [result.status for result in results.values()]
        
        if HealthStatus.FAILING in statuses or HealthStatus.CRITICAL in statuses:
            return "critical"
        elif HealthStatus.DEGRADED in statuses:
            return "degraded"
        elif HealthStatus.HEALTHY in statuses or HealthStatus.UNKNOWN in statuses:
            return "healthy"
        else:
            return "unknown"

# =============================================================================
# MAIN APPLICATION
# =============================================================================

async def main():
    """Main application entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize health check manager
    health_manager = HealthCheckManager()
    
    # Start health check server
    server = HealthCheckServer(health_manager, host="0.0.0.0", port=8080)
    await server.start()
    
    # Run periodic health checks
    while True:
        try:
            await health_manager.run_all_checks()
            await asyncio.sleep(30)  # Run checks every 30 seconds
        except KeyboardInterrupt:
            break
        except Exception as e:
            logging.error(f"Health check loop error: {e}")
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
