use anyhow::Result;
use proof_server::{create_app, initialize_server};

// Use tokio::main macro - consistent with benchmarks
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    // CRITICAL: tracing_subscriber causes 400x performance regression with Rayon!
    // When enabled, proof generation takes 6+ seconds instead of 15-20ms
    // Issue: tracing's thread-local context interferes with Rayon's work-stealing
    // 
    // Enable for startup diagnostics only (disable for production)
    // tracing_subscriber::fmt()
    //     .with_env_filter(
    //         tracing_subscriber::EnvFilter::try_from_default_env()
    //             .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    //     )
    //     .init();
    
    println!("DEBUG_ASSERTIONS = {:?}", cfg!(debug_assertions));
    println!("Build mode: {}", if cfg!(debug_assertions) { "DEBUG" } else { "RELEASE" });
    dotenv::dotenv().ok();
    println!("Optimization level: {}", std::env::var("OPT_LEVEL").unwrap_or_else(|_| "not set".to_string()));

    println!("Starting Location Privacy Proof Server");

    // Initialize server state
    let state = initialize_server().await?;

    // Run the server
    {
        // Create router
        let app = create_app(state).await;

        // Bind to address
        let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3001".to_string());
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        
        println!("🚀 Location Privacy Proof Server");
        println!("   Listening on http://{}", addr);
        println!("");
        println!("📡 Available Endpoints:");
        println!("   GET  /health              - Health check");
        println!("   GET  /api/info            - Server status and commitment info");
        println!("   POST /api/generate-proof  - Generate proximity proof");
        println!("");

        // Run server
        axum::serve(listener, app).await?;
    }

    Ok(())
}
