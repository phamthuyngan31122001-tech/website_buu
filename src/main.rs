#[tokio::main]
async fn main() -> anyhow::Result<()> {
    website_buu::web::run().await
}
