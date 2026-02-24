use s2energy_connection::{S2Role, discovery::S2Discoverer};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut discoverer = S2Discoverer::new(S2Role::Cem).await.unwrap();

    while let Ok(event) = discoverer.next_event().await {
        match event {
            s2energy_connection::discovery::DiscoveryEvent::NewEndpoint { hostname, endpoint } => {
                println!("New endpoint on host {hostname}: {endpoint:?}")
            }
            s2energy_connection::discovery::DiscoveryEvent::RemovedEndpoint { hostname } => println!("Endpoint at {hostname} went away"),
        }
    }
}
