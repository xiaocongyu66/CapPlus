// Emit production documents for browser tests without starting a server.
fn main() {
    println!("{}", serde_json::json!({
        "loader": cap_embed::loader_js(),
        "light": cap_embed::embed_page_with_context("site", "https://page.test", "/assets/widget.js", "", "light"),
        "dark": cap_embed::embed_page_with_context("site", "https://page.test", "/assets/widget.js", "", "dark"),
        "custom": cap_embed::embed_page_with_context("site", "https://page.test", "https://custom.test/widget.js", "", "dark")
    }));
}
