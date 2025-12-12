// Test using EXACT same initialization as production
use anyhow::Result;
use proof_server::{create_app, initialize_server};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    println!("🧪 Testing with EXACT production initialization\n");
    
    // Use EXACT same initialization as production
    let state = initialize_server().await?;
    
    println!("✓ Server initialized");
    println!("\nStarting server on http://127.0.0.1:3005");
    
    let app = create_app(state).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3005").await?;
    
    axum::serve(listener, app).await?;
    
    Ok(())
}
