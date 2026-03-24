use s2energy_connection::{
    Role,
    discovery::{DiscoverableS2Endpoint, advertise},
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let endpoint = DiscoverableS2Endpoint::build_with_pairing(vec![Role::Cem], "https://example.com/".into())
        .unwrap()
        .with_endpoint_name("test endpoint".into())
        .build();
    let advertisement = advertise(8005, endpoint).await.unwrap();

    tokio::signal::ctrl_c().await.ok();

    advertisement.stop().await;
}
