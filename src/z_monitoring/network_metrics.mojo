from python import Python
import sys

# Network quality metrics implementation for Zawra Networking Stack
struct NetworkMetrics:
    var total_packets_sent: Int
    var total_packets_received: Int
    var packet_loss_rate: Float64
    var average_latency_ms: Float64
    var jitter_ms: Float64
    var throughput_mbps: Float64
    var connection_quality_score: Float64
    
    def __init__(self):
        self.total_packets_sent = 0
        self.total_packets_received = 0
        self.packet_loss_rate = 0.0
        self.average_latency_ms = 0.0
        self.jitter_ms = 0.0
        self.throughput_mbps = 0.0
        self.connection_quality_score = 0.0

struct LatencyMeasurement:
    var timestamp: Int
    var latency_ms: Float64
    var measurement_type: String
    
    def __init__(self, timestamp: Int, latency_ms: Float64, measurement_type: String):
        self.timestamp = timestamp
        self.latency_ms = latency_ms
        self.measurement_type = measurement_type

struct PacketLossMeasurement:
    var timestamp: Int
    var packets_lost: Int
    var packets_sent: Int
    var loss_percentage: Float64
    
    def __init__(self, timestamp: Int, packets_lost: Int, packets_sent: Int):
        self.timestamp = timestamp
        self.packets_lost = packets_lost
        self.packets_sent = packets_sent
        if packets_sent > 0:
            self.loss_percentage = (packets_lost / packets_sent) * 100.0
        else:
            self.loss_percentage = 0.0

struct ThroughputMeasurement:
    var timestamp: Int
    var bytes_transferred: Int
    var duration_ms: Float64
    var throughput_mbps: Float64
    
    def __init__(self, timestamp: Int, bytes_transferred: Int, duration_ms: Float64):
        self.timestamp = timestamp
        self.bytes_transferred = bytes_transferred
        self.duration_ms = duration_ms
        if duration_ms > 0:
            self.throughput_mbps = (bytes_transferred * 8.0) / duration_ms / 1000.0
        else:
            self.throughput_mbps = 0.0

struct NetworkQualityAssessment:
    var overall_score: Float64
    var latency_score: Float64
    var packet_loss_score: Float64
    var throughput_score: Float64
    var stability_score: Float64
    var recommendations: List[String]
    
    def __init__(self):
        self.overall_score = 0.0
        self.latency_score = 0.0
        self.packet_loss_score = 0.0
        self.throughput_score = 0.0
        self.stability_score = 0.0
        self.recommendations = List[String]()

class NetworkMonitor:
    var allocator: Any
    var measurements: List[LatencyMeasurement]
    var packet_losses: List[PacketLossMeasurement]
    var throughput_measurements: List[ThroughputMeasurement]
    var baseline_metrics: NetworkMetrics
    var quality_thresholds: Dict[String, Float64]
    
    def __init__(self, allocator: Any):
        self.allocator = allocator
        self.measurements = List[LatencyMeasurement]()
        self.packet_losses = List[PacketLossMeasurement]()
        self.throughput_measurements = List[ThroughputMeasurement]()
        self.baseline_metrics = NetworkMetrics()
        self.quality_thresholds = Dict[String, Float64]()
        
        # Set default quality thresholds
        self.quality_thresholds["max_latency_ms"] = 100.0
        self.quality_thresholds["max_packet_loss_percent"] = 1.0
        self.quality_thresholds["min_throughput_mbps"] = 1.0
        self.quality_thresholds["max_jitter_ms"] = 50.0

    def record_latency(self, measurement: LatencyMeasurement) -> None:
        """Record a latency measurement"""
        self.measurements.append(measurement)
        self.update_baseline_metrics()

    def record_packet_loss(self, measurement: PacketLossMeasurement) -> None:
        """Record a packet loss measurement"""
        self.packet_losses.append(measurement)
        self.update_baseline_metrics()

    def record_throughput(self, measurement: ThroughputMeasurement) -> None:
        """Record a throughput measurement"""
        self.throughput_measurements.append(measurement)
        self.update_baseline_metrics()

    def calculate_real_time_metrics(self) -> NetworkMetrics:
        """Calculate current network metrics based on recent measurements"""
        current_metrics = NetworkMetrics()
        
        # Calculate latency metrics from recent measurements
        if len(self.measurements) > 0:
            recent_measurements = self.measurements[-10:]  # Last 10 measurements
            
            # Average latency
            total_latency = 0.0
            for measurement in recent_measurements:
                total_latency += measurement.latency_ms
            current_metrics.average_latency_ms = total_latency / len(recent_measurements)
            
            # Jitter calculation (standard deviation)
            if len(recent_measurements) > 1:
                variance = 0.0
                for measurement in recent_measurements:
                    diff = measurement.latency_ms - current_metrics.average_latency_ms
                    variance += diff * diff
                current_metrics.jitter_ms = (variance / len(recent_measurements)) ** 0.5
        
        # Calculate packet loss from recent measurements
        if len(self.packet_losses) > 0:
            recent_losses = self.packet_losses[-5:]  # Last 5 measurements
            
            total_sent = 0
            total_lost = 0
            
            for measurement in recent_losses:
                total_sent += measurement.packets_sent
                total_lost += measurement.packets_lost
            
            if total_sent > 0:
                current_metrics.packet_loss_rate = (total_lost / total_sent) * 100.0
                current_metrics.total_packets_sent = total_sent
                current_metrics.total_packets_received = total_sent - total_lost
        
        # Calculate throughput from recent measurements
        if len(self.throughput_measurements) > 0:
            recent_throughput = self.throughput_measurements[-1]  # Most recent
            current_metrics.throughput_mbps = recent_throughput.throughput_mbps
        
        # Calculate overall quality score
        current_metrics.connection_quality_score = self.calculate_quality_score(current_metrics)
        
        return current_metrics

    def calculate_quality_score(self, metrics: NetworkMetrics) -> Float64:
        """Calculate a connection quality score (0-100)"""
        scores = List[Float64]()
        
        # Latency score (lower is better)
        if metrics.average_latency_ms < 50:
            latency_score = 100.0
        elif metrics.average_latency_ms < 100:
            latency_score = 80.0
        elif metrics.average_latency_ms < 200:
            latency_score = 60.0
        elif metrics.average_latency_ms < 500:
            latency_score = 40.0
        else:
            latency_score = 20.0
        
        scores.append(latency_score)
        
        # Packet loss score (lower is better)
        if metrics.packet_loss_rate < 0.1:
            loss_score = 100.0
        elif metrics.packet_loss_rate < 0.5:
            loss_score = 90.0
        elif metrics.packet_loss_rate < 1.0:
            loss_score = 70.0
        elif metrics.packet_loss_rate < 2.0:
            loss_score = 50.0
        else:
            loss_score = 20.0
        
        scores.append(loss_score)
        
        # Throughput score (higher is better)
        if metrics.throughput_mbps > 10:
            throughput_score = 100.0
        elif metrics.throughput_mbps > 5:
            throughput_score = 80.0
        elif metrics.throughput_mbps > 2:
            throughput_score = 60.0
        elif metrics.throughput_mbps > 1:
            throughput_score = 40.0
        else:
            throughput_score = 20.0
        
        scores.append(throughput_score)
        
        # Stability score (based on jitter)
        if metrics.jitter_ms < 10:
            stability_score = 100.0
        elif metrics.jitter_ms < 25:
            stability_score = 80.0
        elif metrics.jitter_ms < 50:
            stability_score = 60.0
        elif metrics.jitter_ms < 100:
            stability_score = 40.0
        else:
            stability_score = 20.0
        
        scores.append(stability_score)
        
        # Calculate weighted average
        total_score = (latency_score * 0.3 + loss_score * 0.25 + 
                      throughput_score * 0.25 + stability_score * 0.2)
        
        return min(100.0, max(0.0, total_score))

    def assess_network_quality(self) -> NetworkQualityAssessment:
        """Provide detailed network quality assessment with recommendations"""
        assessment = NetworkQualityAssessment()
        metrics = self.calculate_real_time_metrics()
        
        assessment.latency_score = self.calculate_latency_score(metrics.average_latency_ms)
        assessment.packet_loss_score = self.calculate_loss_score(metrics.packet_loss_rate)
        assessment.throughput_score = self.calculate_throughput_score(metrics.throughput_mbps)
        assessment.stability_score = self.calculate_stability_score(metrics.jitter_ms)
        
        # Overall weighted score
        assessment.overall_score = (assessment.latency_score * 0.3 + 
                                  assessment.packet_loss_score * 0.25 + 
                                  assessment.throughput_score * 0.25 + 
                                  assessment.stability_score * 0.2)
        
        # Generate recommendations
        assessment.recommendations = self.generate_recommendations(metrics, assessment)
        
        return assessment

    def generate_recommendations(self, metrics: NetworkMetrics, assessment: NetworkQualityAssessment) -> List[String]:
        """Generate actionable recommendations based on metrics"""
        recommendations = List[String]()
        
        if metrics.average_latency_ms > self.quality_thresholds["max_latency_ms"]:
            recommendations.append("High latency detected. Consider checking network congestion or using a CDN.")
        
        if metrics.packet_loss_rate > self.quality_thresholds["max_packet_loss_percent"]:
            recommendations.append("Packet loss detected. Check network cable connections and router health.")
        
        if metrics.throughput_mbps < self.quality_thresholds["min_throughput_mbps"]:
            recommendations.append("Low throughput detected. Consider upgrading network plan or checking ISP.")
        
        if metrics.jitter_ms > self.quality_thresholds["max_jitter_ms"]:
            recommendations.append("High jitter detected. Network stability may be compromised.")
        
        if assessment.overall_score < 50:
            recommendations.append("Poor network quality. Consider switching to a different network or ISP.")
        
        if len(recommendations) == 0:
            recommendations.append("Network quality is good. No immediate action required.")
        
        return recommendations

    def calculate_latency_score(self, latency_ms: Float64) -> Float64:
        """Calculate latency score (0-100)"""
        if latency_ms < 20:
            return 100.0
        elif latency_ms < 50:
            return 90.0
        elif latency_ms < 100:
            return 70.0
        elif latency_ms < 200:
            return 50.0
        elif latency_ms < 500:
            return 30.0
        else:
            return 10.0

    def calculate_loss_score(self, loss_rate: Float64) -> Float64:
        """Calculate packet loss score (0-100)"""
        if loss_rate < 0.01:
            return 100.0
        elif loss_rate < 0.1:
            return 95.0
        elif loss_rate < 0.5:
            return 80.0
        elif loss_rate < 1.0:
            return 60.0
        elif loss_rate < 2.0:
            return 40.0
        else:
            return 20.0

    def calculate_throughput_score(self, throughput_mbps: Float64) -> Float64:
        """Calculate throughput score (0-100)"""
        if throughput_mbps > 50:
            return 100.0
        elif throughput_mbps > 25:
            return 90.0
        elif throughput_mbps > 10:
            return 80.0
        elif throughput_mbps > 5:
            return 60.0
        elif throughput_mbps > 2:
            return 40.0
        elif throughput_mbps > 1:
            return 20.0
        else:
            return 10.0

    def calculate_stability_score(self, jitter_ms: Float64) -> Float64:
        """Calculate stability score (0-100)"""
        if jitter_ms < 5:
            return 100.0
        elif jitter_ms < 10:
            return 90.0
        elif jitter_ms < 25:
            return 70.0
        elif jitter_ms < 50:
            return 50.0
        elif jitter_ms < 100:
            return 30.0
        else:
            return 10.0

    def update_baseline_metrics(self) -> None:
        """Update baseline network metrics"""
        # Keep only recent measurements for performance
        max_measurements = 100
        max_packet_losses = 50
        max_throughput_measurements = 50
        
        if len(self.measurements) > max_measurements:
            self.measurements = self.measurements[-max_measurements:]
        
        if len(self.packet_losses) > max_packet_losses:
            self.packet_losses = self.packet_losses[-max_packet_losses:]
        
        if len(self.throughput_measurements) > max_throughput_measurements:
            self.throughput_measurements = self.throughput_measurements[-max_throughput_measurements:]

    def export_json_metrics(self) -> String:
        """Export current metrics as JSON string"""
        import json
        metrics = self.calculate_real_time_metrics()
        assessment = self.assess_network_quality()
        
        data = {
            "timestamp": int(__import__('time').time() * 1000),
            "network_metrics": {
                "total_packets_sent": metrics.total_packets_sent,
                "total_packets_received": metrics.total_packets_received,
                "packet_loss_rate": metrics.packet_loss_rate,
                "average_latency_ms": metrics.average_latency_ms,
                "jitter_ms": metrics.jitter_ms,
                "throughput_mbps": metrics.throughput_mbps,
                "connection_quality_score": metrics.connection_quality_score
            },
            "quality_assessment": {
                "overall_score": assessment.overall_score,
                "latency_score": assessment.latency_score,
                "packet_loss_score": assessment.packet_loss_score,
                "throughput_score": assessment.throughput_score,
                "stability_score": assessment.stability_score,
                "recommendations": assessment.recommendations
            }
        }
        
        return json.dumps(data, indent=2)

    def get_prometheus_metrics(self) -> String:
        """Export metrics in Prometheus format"""
        metrics = self.calculate_real_time_metrics()
        assessment = self.assess_network_quality()
        
        prometheus_output = String()
        
        # Network quality metrics
        prometheus_output += "# HELP zawra_network_latency_ms Network latency in milliseconds\n"
        prometheus_output += "# TYPE zawra_network_latency_ms gauge\n"
        prometheus_output += f"zawra_network_latency_ms {metrics.average_latency_ms:.3f}\n"
        
        prometheus_output += "# HELP zawra_network_jitter_ms Network jitter in milliseconds\n"
        prometheus_output += "# TYPE zawra_network_jitter_ms gauge\n"
        prometheus_output += f"zawra_network_jitter_ms {metrics.jitter_ms:.3f}\n"
        
        prometheus_output += "# HELP zawra_packet_loss_rate Packet loss rate percentage\n"
        prometheus_output += "# TYPE zawra_packet_loss_rate gauge\n"
        prometheus_output += f"zawra_packet_loss_rate {metrics.packet_loss_rate:.3f}\n"
        
        prometheus_output += "# HELP zawra_throughput_mbps Network throughput in Mbps\n"
        prometheus_output += "# TYPE zawra_throughput_mbps gauge\n"
        prometheus_output += f"zawra_throughput_mbps {metrics.throughput_mbps:.3f}\n"
        
        prometheus_output += "# HELP zawra_connection_quality_score Connection quality score (0-100)\n"
        prometheus_output += "# TYPE zawra_connection_quality_score gauge\n"
        prometheus_output += f"zawra_connection_quality_score {metrics.connection_quality_score:.2f}\n"
        
        prometheus_output += "# HELP zawra_overall_quality_score Overall network quality score (0-100)\n"
        prometheus_output += "# TYPE zawra_overall_quality_score gauge\n"
        prometheus_output += f"zawra_overall_quality_score {assessment.overall_score:.2f}\n"
        
        return prometheus_output

    def set_quality_threshold(self, metric_name: String, threshold_value: Float64) -> None:
        """Set quality threshold for a specific metric"""
        self.quality_thresholds[metric_name] = threshold_value

    def get_quality_threshold(self, metric_name: String) -> Float64:
        """Get quality threshold for a specific metric"""
        return self.quality_thresholds.get(metric_name, 0.0)

# Utility functions for network monitoring
def create_latency_measurement(latency_ms: Float64, measurement_type: String) -> LatencyMeasurement:
    """Create a latency measurement with current timestamp"""
    timestamp = int(__import__('time').time() * 1000)
    return LatencyMeasurement(timestamp, latency_ms, measurement_type)

def create_packet_loss_measurement(packets_lost: Int, packets_sent: Int) -> PacketLossMeasurement:
    """Create a packet loss measurement with current timestamp"""
    timestamp = int(__import__('time').time() * 1000)
    return PacketLossMeasurement(timestamp, packets_lost, packets_sent)

def create_throughput_measurement(bytes_transferred: Int, duration_ms: Float64) -> ThroughputMeasurement:
    """Create a throughput measurement with current timestamp"""
    timestamp = int(__import__('time').time() * 1000)
    return ThroughputMeasurement(timestamp, bytes_transferred, duration_ms)

# Example usage and testing
@always_inline
def example_usage():
    # This would be the usage example in a real application
    allocator = None  # Placeholder for actual allocator
    
    monitor = NetworkMonitor(allocator)
    
    # Record some sample measurements
    latency_measurement = create_latency_measurement(45.5, "icmp_ping")
    monitor.record_latency(latency_measurement)
    
    packet_loss = create_packet_loss_measurement(2, 1000)
    monitor.record_packet_loss(packet_loss)
    
    throughput = create_throughput_measurement(1024 * 1024, 5000.0)  # 1MB in 5 seconds
    monitor.record_throughput(throughput)
    
    # Get current metrics
    current_metrics = monitor.calculate_real_time_metrics()
    assessment = monitor.assess_network_quality()
    
    print(f"Network Quality Score: {assessment.overall_score:.1f}/100")
    print(f"Average Latency: {current_metrics.average_latency_ms:.1f}ms")
    print(f"Packet Loss Rate: {current_metrics.packet_loss_rate:.2f}%")
    print(f"Throughput: {current_metrics.throughput_mbps:.1f}Mbps")