//! HTTP Example - Demonstrating basic HTTP/HTTPS functionality
//! Usage: cargo run --bin http_example

use std::time::Duration;
use anyhow::Result;
use log::info;
use tracing_subscriber;
use zawra_netstack_pipeline::{Pipeline, PipelineConfig, RequestOptions, CacheMode};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    info!("Starting Zawra HTTP Example");

    // Configure pipeline
    let config = PipelineConfig {
        max_concurrent_connections: 50,
        connection_timeout: Duration::from_secs(30),
        dns_timeout: Duration::from_secs(5),
        max_requests_per_host: 10,
        retry_attempts: 3,
        retry_delay: Duration::from_secs(1),
        rate_limit_per_host: Some(10),
    };

    // Create pipeline
    let pipeline = Pipeline::new(config);

    // Example 1: Simple HTTP GET
    println!("\n=== Example 1: Simple HTTP GET ===");
    let options = RequestOptions {
        method: "GET".to_string(),
        headers: std::collections::HashMap::new(),
        timeout: None,
        cache_mode: CacheMode::Default,
        follow_redirects: true,
        verify_ssl: true,
        max_redirects: 5,
    };

    match pipeline.fetch("https://httpbin.org/get".to_string(), options).await {
        Ok(response) => {
            println!("✅ Status: {}", response.status_code);
            println!("📊 Total time: {:?}", response.request_duration);
            if let Some(dns_time) = response.dns_time {
                println!("🌐 DNS time: {:?}", dns_time);
            }
            if let Some(connect_time) = response.connection_time {
                println!("🔌 Connect time: {:?}", connect_time);
            }
            if let Some(handshake_time) = response.handshake_time {
                println!("🔒 TLS handshake: {:?}", handshake_time);
            }
            if let Some(transfer_time) = response.transfer_time {
                println!("📦 Transfer time: {:?}", transfer_time);
            }
            println!("🌐 Final URL: {}", response.final_url);
            println!("🍪 From cache: {}", response.from_cache);
        }
        Err(e) => {
            println!("❌ Error: {:?}", e);
        }
    }

    // Example 2: POST with JSON
    println!("\n=== Example 2: POST with JSON ===");
    let mut headers = std::collections::HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("User-Agent".to_string(), "Zawra-Example/1.0".to_string());

    let json_data = r#"{"test": true, "message": "Hello from Zawra!"}"#;
    let mut post_options = RequestOptions {
        method: "POST".to_string(),
        headers,
        timeout: None,
        cache_mode: CacheMode::NoCache, // Don't cache POST requests
        follow_redirects: true,
        verify_ssl: true,
        max_redirects: 5,
    };

    match pipeline.fetch("https://httpbin.org/post".to_string(), post_options).await {
        Ok(response) => {
            println!("✅ POST Status: {}", response.status_code);
            println!("📝 Response size: {} bytes", response.body.len());
            if response.body.len() < 500 {
                println!("📄 Response body: {}", String::from_utf8_lossy(&response.body));
            }
        }
        Err(e) => {
            println!("❌ POST Error: {:?}", e);
        }
    }

    // Example 3: Batch requests
    println!("\n=== Example 3: Batch Requests ===");
    let urls = vec![
        "https://httpbin.org/delay/1".to_string(),
        "https://httpbin.org/delay/2".to_string(),
        "https://httpbin.org/json".to_string(),
    ];

    println!("🌐 Fetching {} URLs concurrently...", urls.len());
    let start = std::time::Instant::now();

    let mut futures = Vec::new();
    for url in urls {
        let pipeline_clone = pipeline.clone();
        futures.push(async move {
            let options = RequestOptions::default();
            pipeline_clone.fetch(url, options).await
        });
    }

    let results = futures::future::join_all(futures).await;
    
    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(response) => {
                println!("✅ URL {}: Status {}, Duration: {:?}", 
                    i + 1, response.status_code, response.request_duration);
            }
            Err(e) => {
                println!("❌ URL {}: Error: {:?}", i + 1, e);
            }
        }
    }

    println!("⏱️ Total batch time: {:?}", start.elapsed());

    // Example 4: Error handling
    println!("\n=== Example 4: Error Handling ===");
    
    // Test with invalid URL
    match pipeline.fetch("https://invalid-domain-that-does-not-exist.com".to_string(), RequestOptions::default()).await {
        Ok(response) => {
            println!("✅ Unexpected success: {}", response.status_code);
        }
        Err(e) => {
            println!("❌ Expected error: {:?}", e);
        }
    }

    // Test with timeout
    let timeout_options = RequestOptions {
        timeout: Some(Duration::from_millis(100)), // Very short timeout
        ..RequestOptions::default()
    };
    
    match pipeline.fetch("https://httpbin.org/delay/3".to_string(), timeout_options).await {
        Ok(response) => {
            println!("✅ Request completed: {}", response.status_code);
        }
        Err(e) => {
            println!("❌ Timeout error: {:?}", e);
        }
    }

    // Example 5: Headers and metadata
    println!("\n=== Example 5: Headers and Metadata ===");
    let mut header_options = RequestOptions::default();
    header_options.headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    header_options.headers.insert("Cache-Control".to_string(), "no-cache".to_string());

    match pipeline.fetch("https://httpbin.org/headers".to_string(), header_options).await {
        Ok(response) => {
            println!("✅ Headers response:");
            for (key, value) in &response.headers {
                if key.starts_with(':') || key.to_lowercase() == "content-type" {
                    println!("  {}: {}", key, value);
                }
            }
        }
        Err(e) => {
            println!("❌ Headers error: {:?}", e);
        }
    }

    println!("\n🎉 HTTP Example completed successfully!");
    println!("📊 Performance metrics available via pipeline.get_metrics()");

    // Show metrics
    let metrics = pipeline.get_metrics();
    println!("📈 Total requests: {}", metrics.total_requests);
    println!("✅ Successful: {}", metrics.successful_requests);
    println!("❌ Failed: {}", metrics.failed_requests);
    println!("🎯 Hit rate: {:.2}%", metrics.hit_rate * 100.0);
    println!("⚡ Avg request time: {:?}", metrics.average_request_time);

    Ok(())
}