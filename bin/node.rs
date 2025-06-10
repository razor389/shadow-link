// bin/node.rs

use clap::{Arg, App};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shadow_link_rust::network::node::Node;
use shadow_link_rust::network::routing::api::RoutingService;
use shadow_link_rust::network::routing::RoutingManager;
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::types::routing_prefix::RoutingPrefix;
use shadow_link_rust::types::node_info::generate_node_id;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = App::new("ShadowLink Node")
        .version("0.1.0")
        .author("Your Name <your.email@example.com>")
        .about("ShadowLink Node Application")
        .arg(Arg::with_name("address")
            .short('a')
            .long("address")
            .value_name("ADDRESS")
            .help("Sets the address the node will listen on")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("prefix")
            .short('p')
            .long("prefix")
            .value_name("HEX")
            .help("Sets the routing prefix for the node")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("bootstrap_nodes")
            .short('b')
            .long("bootstrap")
            .value_name("ADDRESS")
            .help("Comma-separated list of bootstrap node addresses")
            .takes_value(true)
            .default_value(""))
        .arg(Arg::with_name("pow_difficulty")
            .long("pow-difficulty")
            .value_name("NUMBER")
            .help("Sets the PoW difficulty")
            .takes_value(true)
            .default_value("10"))
        .arg(Arg::with_name("max_ttl")
            .long("max-ttl")
            .value_name("SECONDS")
            .help("Maximum allowed TTL for packets")
            .takes_value(true)
            .default_value("86400"))
        .arg(Arg::with_name("min_m_cost")
            .long("min-m-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 m_cost")
            .takes_value(true)
            .default_value("8"))
        .arg(Arg::with_name("min_t_cost")
            .long("min-t-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 t_cost")
            .takes_value(true)
            .default_value("1"))
        .arg(Arg::with_name("min_p_cost")
            .long("min-p-cost")
            .value_name("NUMBER")
            .help("Minimum Argon2 p_cost")
            .takes_value(true)
            .default_value("1"))
        .arg(Arg::with_name("cleanup_interval")
            .long("cleanup-interval")
            .value_name("SECONDS")
            .help("Interval for cleaning expired packets")
            .takes_value(true)
            .default_value("300"))
        .arg(Arg::with_name("blacklist_duration")
            .long("blacklist-duration")
            .value_name("SECONDS")
            .help("Duration for IP blacklist")
            .takes_value(true)
            .default_value("600"))
        .arg(Arg::with_name("node_discovery_interval")
            .long("discovery-interval")
            .value_name("SECONDS")
            .help("Interval for node discovery")
            .takes_value(true)
            .default_value("3600"))
        .get_matches();

    // Parse CLI args
    let address: SocketAddr = matches
        .value_of("address")
        .unwrap()
        .parse()
        .expect("Invalid address format");

    let prefix_hex = matches.value_of("prefix").unwrap();
    let prefix_bits = u64::from_str_radix(prefix_hex, 16)
        .expect("Invalid prefix hex");
    let prefix_bit_length = (prefix_hex.len() * 4) as u8;
    let prefix = RoutingPrefix::new(prefix_bit_length, prefix_bits);

    let bootstrap_nodes: Vec<SocketAddr> = matches
        .value_of("bootstrap_nodes")
        .unwrap()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("Invalid bootstrap node address"))
        .collect();

    let pow_difficulty: usize = matches
        .value_of("pow_difficulty")
        .unwrap()
        .parse()
        .expect("Invalid PoW difficulty");

    let max_ttl: u64 = matches
        .value_of("max_ttl")
        .unwrap()
        .parse()
        .expect("Invalid max TTL");

    let min_argon2_params = SerializableArgon2Params {
        m_cost: matches.value_of("min_m_cost").unwrap().parse().expect("Invalid m_cost"),
        t_cost: matches.value_of("min_t_cost").unwrap().parse().expect("Invalid t_cost"),
        p_cost: matches.value_of("min_p_cost").unwrap().parse().expect("Invalid p_cost"),
        output_length: Some(32),
    };

    let cleanup_interval = Duration::from_secs(
        matches.value_of("cleanup_interval").unwrap().parse().expect("Invalid interval")
    );
    let blacklist_duration = Duration::from_secs(
        matches.value_of("blacklist_duration").unwrap().parse().expect("Invalid duration")
    );
    let node_discovery_interval = Duration::from_secs(
        matches.value_of("node_discovery_interval").unwrap().parse().expect("Invalid interval")
    );

    // Create and inject routing service
    let node_id = generate_node_id(&address, &prefix);
    let routing_service: Arc<dyn RoutingService> =
        Arc::new(RoutingManager::new(node_id, prefix.clone()));

    // Construct and run the node
    let _node = Node::new(
        routing_service,
        prefix,
        address,
        pow_difficulty,
        max_ttl,
        min_argon2_params,
        cleanup_interval,
        blacklist_duration,
        bootstrap_nodes,
        node_discovery_interval,
    ).await;

    // Keep running
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}