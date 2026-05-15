from collections import Dict, List, Set
from time import monotonic_ns, now
from logging import Logger
from socket import Connection
from crypto import hashlib
from json import dumps, loads

# Zawra Early Hints Support v1.0
# Implements HTTP Early Hints (103) with resource prioritization,
# prefetching strategies, and intelligent hint processing.

alias HINT_STATUS_CODE = 103
alias MAX_HINTS_PER_RESPONSE = 100
alias HINT_CACHE_TTL_SECONDS = 300  # 5 minutes
alias MAX_HINT_QUEUE_SIZE = 1000
alias PRECONNECT_TIMEOUT_MS = 5000
alias DNSPREFETCH_TIMEOUT_MS = 1000

# Early Hints Link Relation Types
alias LINK_REL_PRECONNECT = "preconnect"
alias LINK_REL_DNSPREFETCH = "dns-prefetch"
alias LINK_REL_PRELOAD = "preload"
alias LINK_REL_PREFETCH = "prefetch"
alias LINK_REL_PREINSTALL = "preinstall"
alias LINK_REL_MODULEPRELOAD = "modulepreload"
alias LINK_REL_SERVICEWORKER = "serviceworker"
alias LINK_REL_STYLESHEET = "stylesheet"
alias LINK_REL_SCRIPT = "script"
alias LINK_REL_IMAGE = "image"
alias LINK_REL_FONT = "font"

# Hint Processing Priority
alias HINT_PRIORITY_LOW = 1
alias HINT_PRIORITY_NORMAL = 2
alias HINT_PRIORITY_HIGH = 3
alias HINT_PRIORITY_CRITICAL = 4

# Resource Types for Hint Processing
alias RESOURCE_TYPE_JS = "javascript"
alias RESOURCE_TYPE_CSS = "css"
alias RESOURCE_TYPE_IMAGE = "image"
alias RESOURCE_TYPE_FONT = "font"
alias RESOURCE_TYPE_FETCH = "fetch"
alias RESOURCE_TYPE_XHR = "xhr"
alias RESOURCE_TYPE_MODULE = "module"

@register_passable
struct EarlyHint:
    var hint_id: String
    var relation_type: String
    var url: String
    var attributes: Dict[String, String]
    var priority: Int
    var resource_type: String
    var expires_at: Int
    var processed: Bool
    var execution_status: enum { pending, in_progress, completed, failed, cancelled }
    var timestamp: Int
    var dependencies: List[String]
    var estimated_time_ms: Int
    var cache_key: String
    
    def __init__(inout self, hint_id: String, relation_type: String, url: String):
        self.hint_id = hint_id
        self.relation_type = relation_type
        self.url = url
        self.attributes = Dict[String, String]()
        self.priority = HINT_PRIORITY_NORMAL
        self.resource_type = self.determine_resource_type(url)
        self.expires_at = int(now()) + HINT_CACHE_TTL_SECONDS
        self.processed = False
        self.execution_status = .pending
        self.timestamp = int(now())
        self.dependencies = List[String]()
        self.estimated_time_ms = self.estimate_execution_time()
        self.cache_key = self.generate_cache_key()
    
    def determine_resource_type(self, url: String) -> String:
        """Determine resource type from URL."""
        if url.endswith(".js") or url.endswith(".mjs"):
            return RESOURCE_TYPE_JS
        elif url.endswith(".css"):
            return RESOURCE_TYPE_CSS
        elif url.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg")):
            return RESOURCE_TYPE_IMAGE
        elif url.endswith((".woff", ".woff2", ".ttf", ".otf")):
            return RESOURCE_TYPE_FONT
        elif url.endswith(".json") or url.contains("/api/"):
            return RESOURCE_TYPE_FETCH
        else:
            return RESOURCE_TYPE_XHR  # Default for unknown resources
    
    def estimate_execution_time(self) -> Int:
        """Estimate execution time for this hint."""
        match self.relation_type:
            case LINK_REL_DNSPREFETCH:
                return 50  # DNS lookup typically fast
            case LINK_REL_PRECONNECT:
                return 500  # TCP/TLS handshake
            case LINK_REL_PRELOAD:
                return 1000  # Resource download
            case LINK_REL_PREFETCH:
                return 2000  # Lower priority download
            case _:
                return 1000  # Default estimate
    
    def generate_cache_key(self) -> String:
        """Generate cache key for this hint."""
        var key_data = self.relation_type + ":" + self.url
        for attr_name, attr_value in self.attributes:
            key_data += ":" + attr_name + "=" + attr_value
        return hashlib.sha256(key_data.encode_utf8()).hexdigest()
    
    def is_expired(self) -> Bool:
        """Check if hint has expired."""
        return int(now()) > self.expires_at
    
    def mark_processed(self, status: EarlyHint.ExecutionStatus):
        """Mark hint as processed with given status."""
        self.processed = True
        self.execution_status = status
    
    def should_process(self) -> Bool:
        """Check if hint should be processed."""
        return (not self.processed and 
                not self.is_expired() and 
                self.execution_status != .cancelled)

@register_passable
struct HintProcessor:
    var connection_manager: Any
    var dns_resolver: Any
    var cache: Dict[String, EarlyHint]
    var processed_hints: Set[String]
    var failed_hints: Set[String]
    var execution_queue: List[EarlyHint]
    var background_tasks: Dict[String, Any]
    var logger: Logger
    var hint_statistics: HintStatistics
    
    def __init__(inout self, conn_mgr: Any, dns: Any):
        self.connection_manager = conn_mgr
        self.dns_resolver = dns
        self.cache = Dict[String, EarlyHint]()
        self.processed_hints = Set[String]()
        self.failed_hints = Set[String]()
        self.execution_queue = List[EarlyHint]()
        self.background_tasks = Dict[String, Any]()
        self.logger = Logger("HintProcessor")
        self.hint_statistics = HintStatistics()
    
    def parse_early_hints(self, headers: Dict[String, String]) -> List[EarlyHint]:
        """Parse Early Hints from Link headers."""
        var hints = List[EarlyHint]()
        
        # Look for Link header with rel="preconnect", "dns-prefetch", etc.
        if "link" in headers:
            var link_header = headers["link"]
            var link_entries = link_header.split(",")
            
            for link_entry in link_entries:
                var hint = self.parse_link_entry(link_entry.strip())
                if hint:
                    hints.append(hint)
        
        return hints
    
    def parse_link_entry(self, link_entry: String) -> EarlyHint:
        """Parse individual Link header entry."""
        # Parse: <URL>; rel="relation"; attr1="value1"; attr2="value2"
        var url_start = link_entry.find("<")
        var url_end = link_entry.find(">")
        
        if url_start == -1 or url_end == -1:
            return None
        
        var url = link_entry[url_start + 1:url_end]
        var rest = link_entry[url_end + 1:].strip()
        
        # Extract relation type
        var relation_type = ""
        var attributes = Dict[String, String]()
        
        # Split by semicolons
        var parts = rest.split(";")
        for part in parts:
            var trimmed = part.strip()
            if trimmed.startswith("rel="):
                # Extract relation value
                var rel_value = trimmed[4:].strip()
                if rel_value.startswith('"') and rel_value.endswith('"'):
                    relation_type = rel_value[1:-1]
                elif rel_value.startswith("'") and rel_value.endswith("'"):
                    relation_type = rel_value[1:-1]
                else:
                    relation_type = rel_value
            else:
                # Parse other attributes
                var attr_parts = trimmed.split("=")
                if len(attr_parts) >= 2:
                    var attr_name = attr_parts[0].strip()
                    var attr_value = "=".join(attr_parts[1:]).strip()
                    
                    # Remove quotes if present
                    if attr_value.startswith('"') and attr_value.endswith('"'):
                        attr_value = attr_value[1:-1]
                    elif attr_value.startswith("'") and attr_value.endswith("'"):
                        attr_value = attr_value[1:-1]
                    
                    attributes[attr_name] = attr_value
        
        # Validate relation type
        if not self.is_valid_relation_type(relation_type):
            self.logger.warning("Invalid relation type: " + relation_type)
            return None
        
        # Generate hint ID
        var hint_id = hashlib.sha256((url + relation_type).encode_utf8()).hexdigest()
        
        var hint = EarlyHint(hint_id, relation_type, url)
        hint.attributes = attributes
        
        # Set priority based on attributes
        hint.priority = self.determine_hint_priority(hint)
        
        # Set dependencies if any
        if "as" in attributes:
            var resource_type = attributes["as"]
            var deps = self.get_resource_dependencies(resource_type)
            hint.dependencies = deps
        
        return hint
    
    def is_valid_relation_type(self, relation_type: String) -> Bool:
        """Check if relation type is supported."""
        valid_types = [
            LINK_REL_PRECONNECT, LINK_REL_DNSPREFETCH, LINK_REL_PRELOAD,
            LINK_REL_PREFETCH, LINK_REL_PREINSTALL, LINK_REL_MODULEPRELOAD,
            LINK_REL_SERVICEWORKER, LINK_REL_STYLESHEET, LINK_REL_SCRIPT,
            LINK_REL_IMAGE, LINK_REL_FONT
        ]
        return relation_type in valid_types
    
    def determine_hint_priority(self, hint: EarlyHint) -> Int:
        """Determine hint processing priority."""
        # Critical resources get highest priority
        if hint.relation_type == LINK_REL_PRELOAD and hint.resource_type == RESOURCE_TYPE_CSS:
            return HINT_PRIORITY_CRITICAL
        
        # High priority for important resources
        if (hint.relation_type == LINK_REL_PRELOAD and 
            hint.resource_type in [RESOURCE_TYPE_JS, RESOURCE_TYPE_CSS]):
            return HINT_PRIORITY_HIGH
        
        # Medium priority for preconnects
        if hint.relation_type == LINK_REL_PRECONNECT:
            return HINT_PRIORITY_NORMAL
        
        # Lower priority for prefetches and dns-prefetches
        if hint.relation_type in [LINK_REL_PREFETCH, LINK_REL_DNSPREFETCH]:
            return HINT_PRIORITY_LOW
        
        return HINT_PRIORITY_NORMAL
    
    def get_resource_dependencies(self, resource_type: String) -> List[String]:
        """Get dependencies for a resource type."""
        match resource_type:
            case RESOURCE_TYPE_JS:
                return ["dom-ready"]  # JavaScript often needs DOM
            case RESOURCE_TYPE_CSS:
                return ["dom-ready"]  # CSS needs DOM to be parsed
            case RESOURCE_TYPE_IMAGE:
                return ["layout-complete"]  # Images after layout
            case RESOURCE_TYPE_FONT:
                return ["dom-ready"]  # Fonts need DOM
            case _:
                return List[String]()
    
    def process_hints(self, hints: List[EarlyHint], main_url: String) -> Bool:
        """Process list of Early Hints."""
        self.logger.info("Processing {} hints for {}".format(len(hints), main_url))
        
        # Filter and prioritize hints
        var prioritized_hints = self.prioritize_hints(hints)
        
        # Cache hints
        for hint in prioritized_hints:
            if not hint.is_expired():
                self.cache[hint.cache_key] = hint
        
        # Queue hints for processing
        for hint in prioritized_hints:
            if hint.should_process():
                self.execution_queue.append(hint)
        
        # Process high-priority hints immediately
        self.process_critical_hints()
        
        # Schedule background processing
        self.schedule_background_processing()
        
        return True
    
    def prioritize_hints(self, hints: List[EarlyHint]) -> List[EarlyHint]:
        """Sort hints by priority."""
        # Simple priority-based sorting
        var sorted_hints = sorted(hints, key=lambda h: h.priority, reverse=True)
        return sorted_hints
    
    def process_critical_hints(self) -> Bool:
        """Process critical priority hints immediately."""
        var critical_hints = List[EarlyHint]()
        
        for hint in self.execution_queue:
            if hint.priority >= HINT_PRIORITY_CRITICAL and hint.should_process():
                critical_hints.append(hint)
        
        # Process critical hints
        for hint in critical_hints:
            var success = self.process_hint(hint)
            if success:
                hint.mark_processed(.completed)
                self.processed_hints.add(hint.hint_id)
                self.hint_statistics.increment_processed()
            else:
                hint.mark_processed(.failed)
                self.failed_hints.add(hint.hint_id)
                self.hint_statistics.increment_failed()
            
            # Remove from queue
            self.execution_queue.remove(hint)
        
        return len(critical_hints) > 0
    
    def schedule_background_processing(self):
        """Schedule background processing of remaining hints."""
        # In a real implementation, this would schedule tasks for the event loop
        # For now, we'll simulate background processing
        
        for hint in self.execution_queue:
            if hint.priority == HINT_PRIORITY_LOW:
                # Schedule for later processing
                self.schedule_hint_later(hint)
            else:
                # Process immediately
                var success = self.process_hint(hint)
                if success:
                    hint.mark_processed(.completed)
                    self.processed_hints.add(hint.hint_id)
                    self.hint_statistics.increment_processed()
                else:
                    hint.mark_processed(.failed)
                    self.failed_hints.add(hint.hint_id)
                    self.hint_statistics.increment_failed()
    
    def schedule_hint_later(self, hint: EarlyHint):
        """Schedule hint for later processing."""
        # In real implementation, would add to delayed task queue
        self.logger.debug("Scheduled hint for later: " + hint.url)
    
    def process_hint(self, hint: EarlyHint) -> Bool:
        """Process individual Early Hint."""
        self.logger.debug("Processing hint: {} ({})".format(hint.relation_type, hint.url))
        
        hint.mark_processed(.in_progress)
        
        match hint.relation_type:
            case LINK_REL_DNSPREFETCH:
                return self.process_dns_prefetch(hint)
            case LINK_REL_PRECONNECT:
                return self.process_preconnect(hint)
            case LINK_REL_PRELOAD:
                return self.process_preload(hint)
            case LINK_REL_PREFETCH:
                return self.process_prefetch(hint)
            case _:
                self.logger.warning("Unhandled relation type: " + hint.relation_type)
                return True  # Not a failure, just not implemented
    
    def process_dns_prefetch(self, hint: EarlyHint) -> Bool:
        """Process DNS prefetch hint."""
        try:
            # Extract domain from URL
            var domain = self.extract_domain(hint.url)
            
            # Start DNS resolution in background
            var dns_task = self.dns_resolver.resolve_background(domain, timeout_ms=DNSPREFETCH_TIMEOUT_MS)
            self.background_tasks[hint.hint_id] = dns_task
            
            self.logger.debug("DNS prefetch started for: " + domain)
            return True
            
        except Exception as e:
            self.logger.error("DNS prefetch failed for {}: {}".format(hint.url, str(e)))
            return False
    
    def process_preconnect(self, hint: EarlyHint) -> Bool:
        """Process preconnect hint."""
        try:
            # Extract domain and protocol from URL
            var (domain, port, protocol) = self.parse_url_components(hint.url)
            
            # Start connection establishment
            var conn_task = self.connection_manager.connect_background(
                domain, port, protocol, timeout_ms=PRECONNECT_TIMEOUT_MS
            )
            self.background_tasks[hint.hint_id] = conn_task
            
            self.logger.debug("Preconnect started for: {}:{}".format(domain, port))
            return True
            
        except Exception as e:
            self.logger.error("Preconnect failed for {}: {}".format(hint.url, str(e)))
            return False
    
    def process_preload(self, hint: EarlyHint) -> Bool:
        """Process preload hint."""
        try:
            # Start resource download with high priority
            var resource_type = hint.attributes.get("as", RESOURCE_TYPE_XHR)
            var crossorigin = hint.attributes.get("crossorigin", "")
            
            var load_task = self.download_resource_background(
                hint.url, resource_type, crossorigin, priority=hint.priority
            )
            self.background_tasks[hint.hint_id] = load_task
            
            self.logger.debug("Preload started for: {} (type: {})".format(hint.url, resource_type))
            return True
            
        except Exception as e:
            self.logger.error("Preload failed for {}: {}".format(hint.url, str(e)))
            return False
    
    def process_prefetch(self, hint: EarlyHint) -> Bool:
        """Process prefetch hint (lower priority than preload)."""
        try:
            # Download resource with low priority
            var resource_type = hint.attributes.get("as", RESOURCE_TYPE_XHR)
            var crossorigin = hint.attributes.get("crossorigin", "")
            
            var load_task = self.download_resource_background(
                hint.url, resource_type, crossorigin, priority=HINT_PRIORITY_LOW
            )
            self.background_tasks[hint.hint_id] = load_task
            
            self.logger.debug("Prefetch started for: {} (type: {})".format(hint.url, resource_type))
            return True
            
        except Exception as e:
            self.logger.error("Prefetch failed for {}: {}".format(hint.url, str(e)))
            return False
    
    def download_resource_background(self, url: String, resource_type: String, 
                                   crossorigin: String, priority: Int) -> Any:
        """Start background resource download."""
        # In real implementation, would create background task
        # For now, simulate task creation
        return {
            "url": url,
            "type": resource_type,
            "priority": priority,
            "status": "started",
            "start_time": int(now())
        }
    
    def extract_domain(self, url: String) -> String:
        """Extract domain from URL."""
        if "://" in url:
            var protocol_end = url.find("://")
            var path_start = url.find("/", protocol_end + 3)
            if path_start == -1:
                return url[protocol_end + 3:]
            else:
                return url[protocol_end + 3:path_start]
        elif "/" in url:
            return url.split("/")[0]
        else:
            return url
    
    def parse_url_components(self, url: String) -> Tuple[String, Int, String]:
        """Parse URL into domain, port, and protocol."""
        var domain = self.extract_domain(url)
        var port = 443  # Default HTTPS
        var protocol = "https"
        
        # Extract port if present
        if ":" in domain:
            var parts = domain.split(":")
            domain = parts[0]
            port = int(parts[1])
        
        # Determine protocol from URL
        if url.startswith("http://"):
            protocol = "http"
            port = port if port != 443 else 80
        elif url.startswith("https://"):
            protocol = "https"
        
        return (domain, port, protocol)
    
    def get_cached_hints(self, url: String) -> List[EarlyHint]:
        """Get cached hints for a URL."""
        var hints = List[EarlyHint]()
        
        for hint_key, hint in self.cache:
            if not hint.is_expired() and self.url_matches_hint(url, hint):
                hints.append(hint)
        
        return hints
    
    def url_matches_hint(self, url: String, hint: EarlyHint) -> Bool:
        """Check if URL matches hint pattern."""
        # Simple domain-based matching
        var url_domain = self.extract_domain(url)
        var hint_domain = self.extract_domain(hint.url)
        return url_domain == hint_domain
    
    def cleanup_expired_hints(self) -> Int:
        """Clean up expired hints from cache."""
        var removed_count = 0
        var expired_keys = List[String]()
        
        for hint_key, hint in self.cache:
            if hint.is_expired():
                expired_keys.append(hint_key)
        
        for key in expired_keys:
            del self.cache[key]
            removed_count += 1
        
        self.logger.debug("Cleaned up {} expired hints".format(removed_count))
        return removed_count
    
    def get_processing_statistics(self) -> HintStatistics:
        """Get processing statistics."""
        return self.hint_statistics
    
    def cancel_hint(self, hint_id: String) -> Bool:
        """Cancel processing of a hint."""
        if hint_id in self.processed_hints or hint_id in self.failed_hints:
            return False  # Already processed
        
        # Find hint in cache
        for hint_key, hint in self.cache:
            if hint.hint_id == hint_id:
                hint.mark_processed(.cancelled)
                
                # Cancel background task if exists
                if hint_id in self.background_tasks:
                    # In real implementation, would cancel the background task
                    del self.background_tasks[hint_id]
                
                return True
        
        return False
    
    def reset_statistics(self):
        """Reset processing statistics."""
        self.hint_statistics = HintStatistics()
        self.processed_hints.clear()
        self.failed_hints.clear()

@register_passable
struct HintStatistics:
    var total_hints: Int = 0
    var processed_hints: Int = 0
    var failed_hints: Int = 0
    var cancelled_hints: Int = 0
    var dns_prefetch_count: Int = 0
    var preconnect_count: Int = 0
    var preload_count: Int = 0
    var prefetch_count: Int = 0
    var average_processing_time_ms: Int = 0
    var total_processing_time_ms: Int = 0
    
    def increment_processed(self):
        self.processed_hints += 1
        self.total_hints += 1
    
    def increment_failed(self):
        self.failed_hints += 1
        self.total_hints += 1
    
    def increment_cancelled(self):
        self.cancelled_hints += 1
        self.total_hints += 1
    
    def increment_dns_prefetch(self):
        self.dns_prefetch_count += 1
    
    def increment_preconnect(self):
        self.preconnect_count += 1
    
    def increment_preload(self):
        self.preload_count += 1
    
    def increment_prefetch(self):
        self.prefetch_count += 1
    
    def update_processing_time(self, time_ms: Int):
        self.total_processing_time_ms += time_ms
        if self.total_hints > 0:
            self.average_processing_time_ms = self.total_processing_time_ms // self.total_hints
    
    def get_success_rate(self) -> Float:
        if self.total_hints == 0:
            return 1.0
        return self.processed_hints / self.total_hints
    
    def to_dict(self) -> Dict[String, Any]:
        return {
            "total_hints": self.total_hints,
            "processed_hints": self.processed_hints,
            "failed_hints": self.failed_hints,
            "cancelled_hints": self.cancelled_hints,
            "success_rate": self.get_success_rate(),
            "dns_prefetch_count": self.dns_prefetch_count,
            "preconnect_count": self.preconnect_count,
            "preload_count": self.preload_count,
            "prefetch_count": self.prefetch_count,
            "average_processing_time_ms": self.average_processing_time_ms
        }

# Utility Functions for Early Hints

def create_preconnect_hint(url: String, crossorigin: String = "") -> Dict[String, String]:
    """Create a preconnect hint dictionary."""
    return {
        "rel": LINK_REL_PRECONNECT,
        "href": url,
        "crossorigin": crossorigin
    }

def create_dns_prefetch_hint(url: String) -> Dict[String, String]:
    """Create a DNS prefetch hint dictionary."""
    return {
        "rel": LINK_REL_DNSPREFETCH,
        "href": url
    }

def create_preload_hint(url: String, resource_type: String, crossorigin: String = "", 
                      referrerpolicy: String = "") -> Dict[String, String]:
    """Create a preload hint dictionary."""
    var hint = {
        "rel": LINK_REL_PRELOAD,
        "href": url,
        "as": resource_type,
        "crossorigin": crossorigin
    }
    
    if referrerpolicy:
        hint["referrerpolicy"] = referrerpolicy
    
    return hint

def create_prefetch_hint(url: String, as_type: String = RESOURCE_TYPE_XHR) -> Dict[String, String]:
    """Create a prefetch hint dictionary."""
    return {
        "rel": LINK_REL_PREFETCH,
        "href": url,
        "as": as_type
    }

def link_header_to_dict(link_header: String) -> Dict[String, String]:
    """Parse Link header into dictionary format."""
    var links = Dict[String, String]()
    var entries = link_header.split(",")
    
    for entry in entries:
        var parts = entry.split(";")
        if len(parts) >= 2:
            # Extract URL
            var url_part = parts[0].strip()
            if url_part.startswith("<") and url_part.endswith(">"):
                var url = url_part[1:-1]
                
                # Extract rel and other attributes
                var attributes = Dict[String, String]()
                for i in range(1, len(parts)):
                    var attr = parts[i].strip()
                    if "=" in attr:
                        var attr_parts = attr.split("=", 1)
                        var name = attr_parts[0].strip()
                        var value = attr_parts[1].strip()
                        
                        # Remove quotes
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        elif value.startswith("'") and value.endswith("'"):
                            value = value[1:-1]
                        
                        attributes[name] = value
                
                if "rel" in attributes:
                    var rel_value = attributes["rel"]
                    links[rel_value] = url
    
    return links

# Example usage and integration helpers

def integrate_early_hints(http_response: Dict[String, Any], 
                         connection_manager: Any, 
                         dns_resolver: Any) -> Bool:
    """Integrate Early Hints processing into HTTP response."""
    if "headers" not in http_response:
        return False
    
    var headers = http_response["headers"]
    var processor = HintProcessor(connection_manager, dns_resolver)
    
    # Parse hints from response headers
    var hints = processor.parse_early_hints(headers)
    
    if len(hints) == 0:
        return False
    
    # Process hints for the main URL
    var main_url = http_response.get("url", "")
    return processor.process_hints(hints, main_url)

def extract_critical_resources(hints: List[EarlyHint]) -> Dict[String, List[String]]:
    """Extract critical resources from Early Hints for immediate processing."""
    var critical_resources = Dict[String, List[String]]()
    critical_resources["css"] = List[String]()
    critical_resources["javascript"] = List[String]()
    critical_resources["fonts"] = List[String]()
    critical_resources["images"] = List[String]()
    
    for hint in hints:
        if hint.priority >= HINT_PRIORITY_HIGH:
            match hint.resource_type:
                case RESOURCE_TYPE_CSS:
                    critical_resources["css"].append(hint.url)
                case RESOURCE_TYPE_JS:
                    critical_resources["javascript"].append(hint.url)
                case RESOURCE_TYPE_FONT:
                    critical_resources["fonts"].append(hint.url)
                case RESOURCE_TYPE_IMAGE:
                    critical_resources["images"].append(hint.url)
    
    return critical_resources

def generate_early_hints_response(main_url: String, 
                                critical_resources: Dict[String, List[String]]) -> Dict[String, Any]:
    """Generate Early Hints (103) response."""
    var links = List[String]()
    
    # Add CSS preloads
    for css_url in critical_resources.get("css", []):
        links.append('<{}>; rel="preload"; as="{}"'.format(css_url, "style"))
    
    # Add JS preloads
    for js_url in critical_resources.get("javascript", []):
        links.append('<{}>; rel="preload"; as="{}"'.format(js_url, "script"))
    
    # Add font preloads
    for font_url in critical_resources.get("fonts", []):
        links.append('<{}>; rel="preload"; as="{}"'.format(font_url, "font"))
    
    # Add preconnects for critical domains
    var domains = Set[String]()
    for resource_type, urls in critical_resources.items():
        for url in urls:
            domain = extract_domain_from_url(url)
            domains.add(domain)
    
    for domain in domains:
        links.append('https://{}; rel="preconnect"'.format(domain))
    
    return {
        "status": HINT_STATUS_CODE,
        "headers": {
            "link": ", ".join(links)
        }
    }

def extract_domain_from_url(url: String) -> String:
    """Extract domain from URL for preconnect hints."""
    if "://" in url:
        var protocol_end = url.find("://")
        var path_start = url.find("/", protocol_end + 3)
        if path_start == -1:
            return url[protocol_end + 3:]
        else:
            return url[protocol_end + 3:path_start]
    return url.split("/")[0]