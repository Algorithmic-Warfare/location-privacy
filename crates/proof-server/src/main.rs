use anyhow::Result;
use proof_server::{create_app, initialize_server};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    info!("Starting Location Privacy Proof Server");

    // Initialize server state
    let state = initialize_server().await?;

    // Create router
    let app = create_app(state).await;

    // Bind to address
    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3001".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    info!("🚀 Location Privacy Proof Server");
    info!("   Listening on http://{}", addr);
    info!("");
    info!("📡 Available Endpoints:");
    info!("   GET  /health              - Health check");
    info!("   GET  /api/info            - Server status and commitment info");
    info!("   POST /api/generate-proof  - Generate proximity proof");
    info!("");

    // Run server
    axum::serve(listener, app).await?;

    Ok(())
}
