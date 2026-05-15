from python import Python
from time import sleep, time
import json
import asyncio
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import websockets
import queue
import datetime

# Real-time monitoring dashboard for Zawra Networking Stack
struct MetricDataPoint:
    var timestamp: Int
    var metric_name: String
    var value: Float64
    var labels: Dict[String, String]
    
    def __init__(self, timestamp: Int, metric_name: String, value: Float64):
        self.timestamp = timestamp
        self.metric_name = metric_name
        self.value = value
        self.labels = Dict[String, String]()

struct DashboardWidget:
    var widget_id: String
    var widget_type: WidgetType
    var title: String
    var position: DashboardPosition
    var size: DashboardSize
    var refresh_interval_ms: Int
    var data_source: String
    
    def __init__(self, widget_id: String, widget_type: WidgetType, title: String):
        self.widget_id = widget_id
        self.widget_type = widget_type
        self.title = title
        self.position = DashboardPosition(0, 0)
        self.size = DashboardSize(400, 300)
        self.refresh_interval_ms = 5000
        self.data_source = "default"

struct WidgetType:
    alias LINE_CHART = "line_chart"
    alias BAR_CHART = "bar_chart"  
    alias GAUGE = "gauge"
    alias TABLE = "table"
    alias HEATMAP = "heatmap"
    alias ALERT_LIST = "alert_list"

struct DashboardPosition:
    var x: Int
    var y: Int
    
    def __init__(self, x: Int, y: Int):
        self.x = x
        self.y = y

struct DashboardSize:
    var width: Int
    var height: Int
    
    def __init__(self, width: Int, height: Int):
        self.width = width
        self.height = height

struct AlertData:
    var alert_id: String
    var severity: AlertSeverity
    var title: String
    var message: String
    var timestamp: Int
    var source: String
    var acknowledged: Bool
    
    def __init__(self, alert_id: String, severity: AlertSeverity, title: String, message: String):
        self.alert_id = alert_id
        self.severity = severity
        self.title = title
        self.message = message
        self.timestamp = int(time() * 1000)
        self.source = "zawra-netstack"
        self.acknowledged = False

struct AlertSeverity:
    alias INFO = "info"
    alias WARNING = "warning" 
    alias CRITICAL = "critical"
    alias EMERGENCY = "emergency"

class MetricsStreamer:
    """Manages real-time metrics streaming via WebSocket"""
    var connected_clients: List[websockets.WebSocketServerProtocol]
    var metrics_queue: queue.Queue
    var is_streaming: Bool
    var max_queue_size: Int
    
    def __init__(self):
        self.connected_clients = List[websockets.WebSocketServerProtocol]()
        self.metrics_queue = queue.Queue(maxsize=1000)
        self.is_streaming = False
        self.max_queue_size = 1000

    def start_streaming(self):
        """Start the metrics streaming service"""
        self.is_streaming = True
        streaming_thread = threading.Thread(target=self._streaming_loop)
        streaming_thread.daemon = True
        streaming_thread.start()

    def stop_streaming(self):
        """Stop the metrics streaming service"""
        self.is_streaming = False

    def add_metric(self, metric: MetricDataPoint):
        """Add a metric to the streaming queue"""
        try:
            if not self.metrics_queue.full():
                self.metrics_queue.put_nowait(metric.to_json())
        except queue.Full:
            # Drop oldest metric to make room for new one
            try:
                self.metrics_queue.get_nowait()
                self.metrics_queue.put_nowait(metric.to_json())
            except queue.Empty:
                pass

    async def _streaming_loop(self):
        """Main streaming loop that sends metrics to connected clients"""
        while self.is_streaming:
            try:
                if not self.metrics_queue.empty():
                    metric_data = self.metrics_queue.get_nowait()
                    
                    # Send to all connected clients
                    disconnected_clients = []
                    for client in self.connected_clients:
                        try:
                            await client.send(metric_data)
                        except websockets.exceptions.ConnectionClosed:
                            disconnected_clients.append(client)
                    
                    # Remove disconnected clients
                    for client in disconnected_clients:
                        self.connected_clients.remove(client)
                
                await asyncio.sleep(0.1)  # 100ms intervals
            except Exception as e:
                print(f"Streaming error: {e}")
                await asyncio.sleep(1)

class DashboardServer:
    """HTTP server for the monitoring dashboard"""
    var port: Int
    var streamer: MetricsStreamer
    var dashboard_data: DashboardData
    var http_server: HTTPServer
    
    def __init__(self, port: Int = 8080):
        self.port = port
        self.streamer = MetricsStreamer()
        self.dashboard_data = DashboardData()
        
    def start_server(self):
        """Start the dashboard HTTP server"""
        server_thread = threading.Thread(target=self._start_http_server)
        server_thread.daemon = True
        server_thread.start()
        
        # Start WebSocket server
        websocket_thread = threading.Thread(target=self._start_websocket_server)
        websocket_thread.daemon = True
        websocket_thread.start()
        
        self.streamer.start_streaming()
        print(f"Dashboard server started on port {self.port}")

    def _start_http_server(self):
        """Start HTTP server for dashboard web interface"""
        class DashboardHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/" or self.path == "/dashboard":
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(DashboardServer.generate_dashboard_html().encode())
                elif self.path == "/api/metrics":
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(self.server.dashboard_data.get_current_metrics()).encode())
                elif self.path == "/api/alerts":
                    self.send_response(200)
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(self.server.dashboard_data.get_current_alerts()).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        DashboardHandler.dashboard_server = self  # Reference to main server
        
        self.http_server = HTTPServer(('localhost', self.port), DashboardHandler)
        self.http_server.serve_forever()

    def _start_websocket_server(self):
        """Start WebSocket server for real-time metrics"""
        async def handle_websocket(websocket, path):
            self.streamer.connected_clients.append(websocket)
            print(f"New WebSocket client connected: {websocket.remote_address}")
            
            try:
                await websocket.wait_closed()
            finally:
                if websocket in self.streamer.connected_clients:
                    self.streamer.connected_clients.remove(websocket)
                print(f"WebSocket client disconnected: {websocket.remote_address}")

        start_server = websockets.serve(handle_websocket, 'localhost', self.port + 1)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

    @staticmethod
    def generate_dashboard_html() -> String:
        """Generate the dashboard HTML interface"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Zawra Networking Stack Monitor</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                .dashboard-header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
                .metric-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .metric-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #2c3e50; }
                .metric-value { font-size: 32px; font-weight: bold; color: #27ae60; }
                .metric-unit { font-size: 14px; color: #7f8c8d; }
                .alerts-section { background: white; border-radius: 8px; padding: 20px; margin-top: 20px; }
                .alert-item { padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid; }
                .alert-info { background: #d1ecf1; border-left-color: #0c5460; }
                .alert-warning { background: #fff3cd; border-left-color: #856404; }
                .alert-critical { background: #f8d7da; border-left-color: #721c24; }
                .connection-status { display: flex; align-items: center; gap: 10px; }
                .status-indicator { width: 12px; height: 12px; border-radius: 50%; }
                .status-connected { background-color: #28a745; }
                .status-disconnected { background-color: #dc3545; }
            </style>
        </head>
        <body>
            <div class="dashboard-header">
                <h1>Zawra Networking Stack Monitor</h1>
                <div class="connection-status">
                    <div id="connection-status" class="status-indicator status-disconnected"></div>
                    <span id="connection-text">Connecting...</span>
                </div>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-title">Network Latency</div>
                    <div class="metric-value"><span id="latency-value">0</span></div>
                    <div class="metric-unit">milliseconds</div>
                    <canvas id="latency-chart"></canvas>
                </div>
                
                <div class="metric-card">
                    <div class="metric-title">Throughput</div>
                    <div class="metric-value"><span id="throughput-value">0</span></div>
                    <div class="metric-unit">Mbps</div>
                    <canvas id="throughput-chart"></canvas>
                </div>
                
                <div class="metric-card">
                    <div class="metric-title">Packet Loss</div>
                    <div class="metric-value"><span id="packet-loss-value">0</span></div>
                    <div class="metric-unit">%</div>
                    <canvas id="packet-loss-chart"></canvas>
                </div>
                
                <div class="metric-card">
                    <div class="metric-title">Connection Quality</div>
                    <div class="metric-value"><span id="quality-score">0</span></div>
                    <div class="metric-unit">/100</div>
                    <canvas id="quality-chart"></canvas>
                </div>
            </div>
            
            <div class="alerts-section">
                <h2>Active Alerts</h2>
                <div id="alerts-container"></div>
            </div>

            <script>
                // Initialize WebSocket connection
                const socket = io('ws://localhost:8081');
                const connectionStatus = document.getElementById('connection-status');
                const connectionText = document.getElementById('connection-text');
                
                socket.on('connect', function() {
                    connectionStatus.className = 'status-indicator status-connected';
                    connectionText.textContent = 'Connected';
                });
                
                socket.on('disconnect', function() {
                    connectionStatus.className = 'status-indicator status-disconnected';
                    connectionText.textContent = 'Disconnected';
                });
                
                // Chart instances
                let latencyChart, throughputChart, packetLossChart, qualityChart;
                
                // Initialize charts
                function initCharts() {
                    const chartConfig = {
                        type: 'line',
                        options: {
                            responsive: true,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    };
                    
                    latencyChart = new Chart(document.getElementById('latency-chart'), chartConfig);
                    throughputChart = new Chart(document.getElementById('throughput-chart'), chartConfig);
                    packetLossChart = new Chart(document.getElementById('packet-loss-chart'), chartConfig);
                    qualityChart = new Chart(document.getElementById('quality-chart'), chartConfig);
                }
                
                // Update metrics
                function updateMetrics(metricData) {
                    if (metricData.metric_name === 'network_latency') {
                        document.getElementById('latency-value').textContent = metricData.value.toFixed(2);
                        updateChart(latencyChart, metricData);
                    } else if (metricData.metric_name === 'throughput') {
                        document.getElementById('throughput-value').textContent = metricData.value.toFixed(2);
                        updateChart(throughputChart, metricData);
                    } else if (metricData.metric_name === 'packet_loss') {
                        document.getElementById('packet-loss-value').textContent = metricData.value.toFixed(2);
                        updateChart(packetLossChart, metricData);
                    } else if (metricData.metric_name === 'quality_score') {
                        document.getElementById('quality-score').textContent = Math.round(metricData.value);
                        updateChart(qualityChart, metricData);
                    }
                }
                
                // Update chart with new data
                function updateChart(chart, metricData) {
                    const now = new Date(metricData.timestamp);
                    chart.data.labels.push(now.toLocaleTimeString());
                    chart.data.datasets[0].data.push(metricData.value);
                    
                    // Keep only last 20 data points
                    if (chart.data.labels.length > 20) {
                        chart.data.labels.shift();
                        chart.data.datasets[0].data.shift();
                    }
                    
                    chart.update('none');
                }
                
                // Handle incoming WebSocket messages
                socket.on('metrics', function(data) {
                    updateMetrics(JSON.parse(data));
                });
                
                // Load initial data
                fetch('/api/metrics')
                    .then(response => response.json())
                    .then(data => {
                        console.log('Initial metrics loaded:', data);
                    });
                
                // Load initial alerts
                fetch('/api/alerts')
                    .then(response => response.json())
                    .then(data => {
                        updateAlerts(data);
                    });
                
                function updateAlerts(alerts) {
                    const container = document.getElementById('alerts-container');
                    container.innerHTML = '';
                    
                    alerts.forEach(alert => {
                        const alertDiv = document.createElement('div');
                        alertDiv.className = `alert-item alert-${alert.severity}`;
                        alertDiv.innerHTML = `
                            <strong>${alert.title}</strong><br>
                            ${alert.message}<br>
                            <small>${new Date(alert.timestamp).toLocaleString()}</small>
                        `;
                        container.appendChild(alertDiv);
                    });
                }
                
                // Initialize dashboard
                initCharts();
                
                // Periodic refresh of static data
                setInterval(function() {
                    fetch('/api/alerts')
                        .then(response => response.json())
                        .then(data => updateAlerts(data));
                }, 10000); // Refresh alerts every 10 seconds
            </script>
        </body>
        </html>
        """

class DashboardData:
    """Manages dashboard data and state"""
    var current_metrics: Dict[String, Float64]
    var historical_data: Dict[String, List[MetricDataPoint]]
    var active_alerts: List[AlertData]
    var widgets: List[DashboardWidget]
    
    def __init__(self):
        self.current_metrics = Dict[String, Float64]()
        self.historical_data = Dict[String, List[MetricDataPoint]]()
        self.active_alerts = List[AlertData]()
        self.widgets = List[DashboardWidget]()
        self.initialize_default_metrics()
        self.initialize_default_widgets()

    def initialize_default_metrics(self):
        """Initialize default metric values"""
        self.current_metrics["network_latency"] = 0.0
        self.current_metrics["throughput"] = 0.0
        self.current_metrics["packet_loss"] = 0.0
        self.current_metrics["quality_score"] = 0.0
        self.current_metrics["active_connections"] = 0
        self.current_metrics["dns_lookup_time"] = 0.0
        self.current_metrics["tcp_connect_time"] = 0.0
        self.current_metrics["tls_handshake_time"] = 0.0
        self.current_metrics["http_request_time"] = 0.0

    def initialize_default_widgets(self):
        """Initialize default dashboard widgets"""
        # Add default widgets
        latency_widget = DashboardWidget("latency", "line_chart", "Network Latency")
        latency_widget.position = DashboardPosition(0, 0)
        latency_widget.size = DashboardSize(400, 300)
        latency_widget.refresh_interval_ms = 1000
        
        throughput_widget = DashboardWidget("throughput", "line_chart", "Throughput")
        throughput_widget.position = DashboardPosition(1, 0)
        throughput_widget.size = DashboardSize(400, 300)
        throughput_widget.refresh_interval_ms = 1000
        
        self.widgets.append(latency_widget)
        self.widgets.append(throughput_widget)

    def update_metric(self, metric_name: String, value: Float64):
        """Update a metric value"""
        self.current_metrics[metric_name] = value
        
        # Add to historical data
        if metric_name not in self.historical_data:
            self.historical_data[metric_name] = List[MetricDataPoint]()
        
        data_point = MetricDataPoint(int(time() * 1000), metric_name, value)
        self.historical_data[metric_name].append(data_point)
        
        # Keep only recent data points (last hour)
        max_points = 3600
        if len(self.historical_data[metric_name]) > max_points:
            self.historical_data[metric_name] = self.historical_data[metric_name][-max_points:]

    def add_alert(self, alert: AlertData):
        """Add a new alert"""
        self.active_alerts.append(alert)

    def acknowledge_alert(self, alert_id: String) -> Bool:
        """Acknowledge an alert"""
        for alert in self.active_alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def get_current_metrics(self) -> Dict[String, Float64]:
        """Get current metrics snapshot"""
        return self.current_metrics.copy()

    def get_current_alerts(self) -> List[Dict[String, Any]]:
        """Get current alerts (unacknowledged only)"""
        unacknowledged_alerts = List[Dict[String, Any]]()
        for alert in self.active_alerts:
            if not alert.acknowledged:
                alert_dict = Dict[String, Any]()
                alert_dict["alert_id"] = alert.alert_id
                alert_dict["severity"] = alert.severity
                alert_dict["title"] = alert.title
                alert_dict["message"] = alert.message
                alert_dict["timestamp"] = alert.timestamp
                alert_dict["source"] = alert.source
                unacknowledged_alerts.append(alert_dict)
        return unacknowledged_alerts

    def get_historical_data(self, metric_name: String, time_range_ms: Int) -> List[MetricDataPoint]:
        """Get historical data for a specific metric within time range"""
        if metric_name not in self.historical_data:
            return List[MetricDataPoint]()
        
        current_time = int(time() * 1000)
        cutoff_time = current_time - time_range_ms
        
        filtered_data = List[MetricDataPoint]()
        for data_point in self.historical_data[metric_name]:
            if data_point.timestamp >= cutoff_time:
                filtered_data.append(data_point)
        
        return filtered_data

# Utility functions
def create_metric_point(metric_name: String, value: Float64) -> MetricDataPoint:
    """Create a new metric data point with current timestamp"""
    return MetricDataPoint(int(time() * 1000), metric_name, value)

def create_alert(severity: String, title: String, message: String) -> AlertData:
    """Create a new alert with generated ID"""
    alert_id = f"alert_{int(time() * 1000)}"
    return AlertData(alert_id, severity, title, message)

# Example usage and simulation
def example_dashboard_usage():
    """Example of how to use the dashboard system"""
    # Start dashboard server
    dashboard = DashboardServer(port=8080)
    dashboard.start_server()
    
    # Simulate some metrics updates
    import random
    
    while True:
        # Simulate network metrics
        latency = random.uniform(10, 100)
        throughput = random.uniform(1, 50)
        packet_loss = random.uniform(0, 2)
        quality_score = random.uniform(60, 100)
        
        # Update dashboard data
        dashboard.dashboard_data.update_metric("network_latency", latency)
        dashboard.dashboard_data.update_metric("throughput", throughput)
        dashboard.dashboard_data.update_metric("packet_loss", packet_loss)
        dashboard.dashboard_data.update_metric("quality_score", quality_score)
        
        # Stream metrics to connected clients
        for metric_name, value in dashboard.dashboard_data.current_metrics.items():
            metric_point = create_metric_point(metric_name, value)
            dashboard.streamer.add_metric(metric_point)
        
        sleep(1)  # Update every second