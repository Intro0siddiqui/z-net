# Zawra Deployment Guide 🚀

This guide covers the deployment and operational aspects of the Zawra Networking Stack in a production environment.

## 📦 Deployment Models

### 1. Embedded Browser Integration
The stack is designed to be compiled as a set of shared libraries and integrated directly into the browser process.

### 2. Standalone Proxy Mode
Zawra can also be deployed as a high-performance networking proxy for backend services.

## 🚀 Production Best Practices

- **Build Optimization**: Always use release builds for production.
  ```bash
  ./build.sh package
  ```
- **Platform Specifics**: Ensure mbedTLS is properly configured for your target platform.
- **Resource Limits**: Configure performance budgets in `z_monitoring` to prevent resource exhaustion.

## 🛠️ Operations & Monitoring

The `deployment/` directory contains various scripts for operational management:

- `src/z_health/checker.zig`: Automated health monitoring of the stack.
- `src/z_monitoring/dashboard.zig`: Dashboard and metrics visualization.
- `performance_tuning.zig`: Scripts for optimizing runtime parameters based on system load.
- `backup_recovery.zig`: Procedures for backing up and restoring `z_storage` and `z_cache` data.
- `rolling_updates.zig`: Orchestrates zero-downtime updates of the networking components.

## 📊 Monitoring Integration

Zawra provides built-in support for real-time monitoring via `z_monitoring`.

### Key Metrics to Track
- **Request Latency**: Breakdown by DNS, TLS, and Transfer times.
- **Error Rates**: Tracking 4xx and 5xx responses.
- **Cache Hit Rate**: Efficiency of the `z_cache` layer.
- **Resource Usage**: Memory and CPU footprint of the networking stack.

## 🛡️ Security Hardening

- **HSTS Preloading**: Ensure your instance is updated with the latest HSTS preload lists using `z_security`.
- **Certificate Pinning**: Configure expected certificates for critical endpoints.
- **CORS/CSP Enforcement**: Regularly audit and update policies in `z_policy`.

## 🆘 Troubleshooting

- **Logs**: Check the system logs for messages from the Zawra components.
- **Benchmarks**: Run `./build.sh benchmark` to identify performance bottlenecks.
- **Validation**: Use the `z_config` validator to ensure your production config is correct.

---

*For detailed configuration options, refer to the [API Reference](API_REFERENCE.md).*
