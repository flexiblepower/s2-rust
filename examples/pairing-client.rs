use reqwest::Url;
use s2energy::pairing::{Role, pair_client, transport::*};

const PAIRING_TOKEN: &[u8] = &[1, 2, 3];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let node_description = S2NodeDescription {
        id: S2NodeId(String::from("12121212")),
        brand: String::from("super-reliable-corp"),
        logo_uri: None,
        type_: String::from("fancy"),
        model_name: String::from("the best"),
        user_defined_name: None,
        role: S2Role::Rm,
    };
    let endpoint_description = S2EndpointDescription {
        name: None,
        logo_uri: None,
        deployment: None,
    };
    let id = PairingS2NodeId(String::from("elfkje"));

    let url = Url::parse("http://127.0.0.1:8005").unwrap();
    let mut rng = rand::rng();
    pair_client(
        &mut rng,
        url,
        PAIRING_TOKEN,
        //        Role::CommunicationServer {
        //            initiate_connection_url: Url::parse("http://fake.com").unwrap(),
        //            access_token: AccessToken(String::from("AABB")),
        //        },
        Role::CommunicationClient,
        vec![ConnectionVersion("v1".into())],
        node_description,
        endpoint_description,
        id,
    )
    .await
    .unwrap();
}
