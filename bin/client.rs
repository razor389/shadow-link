// bin/client.rs

use clap::{value_parser, Arg, ArgAction, Command};
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

    let matches = Command::new("ShadowLink Client")
        .version("0.1.0")
        .author("Your Name <your.email@example.com>")
        .about("ShadowLink Client Application")
        .arg(
            Arg::new("bootstrap_node")
                .short('b')
                .long("bootstrap")
                .value_name("ADDRESS")
                .help("Address of the bootstrap node to connect to")
                .required(true)
                .value_parser(value_parser!(SocketAddr)),
        )
        .arg(
            Arg::new("prefix")
                .short('p')
                .long("prefix")
                .value_name("HEX")
                .help("Optional prefix for the client's address")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("length")
                .short('l')
                .long("length")
                .value_name("BITS")
                .help("Optional length of the client's address prefix")
                .value_parser(value_parser!(u8)),
        )
        .arg(
            Arg::new("max_prefix_length")
                .long("max-prefix")
                .value_name("BITS")
                .help("Maximum prefix length to search for (default: 64)")
                .default_value("64")
                .value_parser(value_parser!(u8)),
        )
        .arg(
            Arg::new("min_m_cost")
                .long("min-m-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 m_cost parameter")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("min_t_cost")
                .long("min-t-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 t_cost parameter")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("min_p_cost")
                .long("min-p-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 p_cost parameter")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("require_exact_argon2")
                .long("exact-argon2")
                .help("Require nodes to have exact Argon2 parameters")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    // Parse CLI args
    let bootstrap_node_address = *matches
        .get_one::<SocketAddr>("bootstrap_node")
        .expect("Bootstrap node is required");

    let prefix = matches.get_one::<String>("prefix").map(|hex_str| {
        let bits = u64::from_str_radix(hex_str, 16).expect("Invalid prefix hex");
        let bit_length = (hex_str.len() * 4) as u8;
        RoutingPrefix::new(bit_length, bits)
    });

    let length = matches.get_one::<u8>("length").copied();

    let max_prefix_length = *matches
        .get_one::<u8>("max_prefix_length")
        .expect("Max prefix length has a default");

    let min_argon2_params = SerializableArgon2Params {
        m_cost: matches
            .get_one::<u32>("min_m_cost")
            .copied()
            .unwrap_or(8),
        t_cost: matches
            .get_one::<u32>("min_t_cost")
            .copied()
            .unwrap_or(1),
        p_cost: matches
            .get_one::<u32>("min_p_cost")
            .copied()
            .unwrap_or(1),
        output_length: Some(32),
    };

    let require_exact_argon2 = matches.get_flag("require_exact_argon2");

    // Inject a routing service based on DHT
    let routing_service: Arc<dyn RoutingService> =
        Arc::new(RoutingManager::new([0u8; 20], prefix.unwrap_or_default()));

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
