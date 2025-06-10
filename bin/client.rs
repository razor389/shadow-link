// bin/client.rs

use clap::{Arg, App};
use std::net::SocketAddr;
use std::sync::Arc;

use shadow_link_rust::network::client::Client;
use shadow_link_rust::network::routing::api::RoutingService;
use shadow_link_rust::network::routing::RoutingManager;
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::types::routing_prefix::RoutingPrefix;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = App::new("ShadowLink Client")
        .version("0.1.0")
        .author("Your Name <your.email@example.com>")
        .about("ShadowLink Client Application")
        .arg(Arg::with_name("bootstrap_node")
            .short('b')
            .long("bootstrap")
            .value_name("ADDRESS")
            .help("Address of the bootstrap node to connect to")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("prefix")
            .short('p')
            .long("prefix")
            .value_name("HEX")
            .help("Optional prefix for the client's address")
            .takes_value(true))
        .arg(Arg::with_name("length")
            .short('l')
            .long("length")
            .value_name("BITS")
            .help("Optional length of the client's address prefix")
            .takes_value(true))
        .arg(Arg::with_name("max_prefix_length")
            .long("max-prefix")
            .value_name("BITS")
            .help("Maximum prefix length to search for (default: 64)")
            .takes_value(true)
            .default_value("64"))
        .arg(Arg::with_name("min_m_cost")
            .long("min-m-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 m_cost parameter")
            .takes_value(true))
        .arg(Arg::with_name("min_t_cost")
            .long("min-t-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 t_cost parameter")
            .takes_value(true))
        .arg(Arg::with_name("min_p_cost")
            .long("min-p-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 p_cost parameter")
            .takes_value(true))
        .arg(Arg::with_name("require_exact_argon2")
            .long("exact-argon2")
            .help("Require nodes to have exact Argon2 parameters")
            .takes_value(false))
        .get_matches();

    // Parse CLI args
    let bootstrap_node_address: SocketAddr = matches
        .value_of("bootstrap_node")
        .unwrap()
        .parse()
        .expect("Invalid bootstrap node address");

    let prefix = matches.value_of("prefix").map(|hex_str| {
        let bits = u64::from_str_radix(hex_str, 16)
            .expect("Invalid prefix hex");
        let bit_length = (hex_str.len() * 4) as u8;
        RoutingPrefix::new(bit_length, bits)
    });

    let length = matches
        .value_of("length")
        .map(|s| s.parse::<u8>().expect("Invalid length"));

    let max_prefix_length: u8 = matches
        .value_of("max_prefix_length")
        .unwrap()
        .parse()
        .expect("Invalid max prefix length");

    let min_argon2_params = {
        let m_cost = matches.value_of("min_m_cost").map(|s| s.parse().expect("Invalid m_cost"));
        let t_cost = matches.value_of("min_t_cost").map(|s| s.parse().expect("Invalid t_cost"));
        let p_cost = matches.value_of("min_p_cost").map(|s| s.parse().expect("Invalid p_cost"));
        SerializableArgon2Params {
            m_cost: m_cost.unwrap_or(8),
            t_cost: t_cost.unwrap_or(1),
            p_cost: p_cost.unwrap_or(1),
            output_length: Some(32),
        }
    };

    let require_exact_argon2 = matches.is_present("require_exact_argon2");

    // Inject a routing service based on DHT
    let routing_service: Arc<dyn RoutingService> = Arc::new(
        RoutingManager::new([0u8; 20], prefix.unwrap_or_default())
    );

    // Build client
    let mut client = Client::new(
        routing_service,
        prefix,
        length,
        max_prefix_length,
        min_argon2_params,
        require_exact_argon2,
        bootstrap_node_address,
    );

    // Kick off subscription and message processing
    client.find_connect_subscribe().await;

    // Keep alive
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}