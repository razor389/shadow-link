// bin/node.rs

use clap::{value_parser, Arg, Command};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shadow_link_rust::network::node::Node;
use shadow_link_rust::network::routing::api::RoutingService;
use shadow_link_rust::network::routing::RoutingManager;
use shadow_link_rust::types::argon2_params::SerializableArgon2Params;
use shadow_link_rust::types::node_info::generate_node_id;
use shadow_link_rust::types::routing_prefix::RoutingPrefix;

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("ShadowLink Node")
        .version("0.1.0")
        .author("Your Name <your.email@example.com>")
        .about("ShadowLink Node Application")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Sets the address the node will listen on")
                .required(true)
                .value_parser(value_parser!(SocketAddr)),
        )
        .arg(
            Arg::new("prefix")
                .short('p')
                .long("prefix")
                .value_name("HEX")
                .help("Sets the routing prefix for the node")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("bootstrap_nodes")
                .short('b')
                .long("bootstrap")
                .value_name("ADDRESS")
                .help("Comma-separated list of bootstrap node addresses")
                .default_value("")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("pow_difficulty")
                .long("pow-difficulty")
                .value_name("NUMBER")
                .help("Sets the PoW difficulty")
                .default_value("10")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("max_ttl")
                .long("max-ttl")
                .value_name("SECONDS")
                .help("Maximum allowed TTL for packets")
                .default_value("86400")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("min_m_cost")
                .long("min-m-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 m_cost")
                .default_value("8")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("min_t_cost")
                .long("min-t-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 t_cost")
                .default_value("1")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("min_p_cost")
                .long("min-p-cost")
                .value_name("NUMBER")
                .help("Minimum Argon2 p_cost")
                .default_value("1")
                .value_parser(value_parser!(u32)),
        )
        .arg(
            Arg::new("cleanup_interval")
                .long("cleanup-interval")
                .value_name("SECONDS")
                .help("Interval for cleaning expired packets")
                .default_value("300")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("blacklist_duration")
                .long("blacklist-duration")
                .value_name("SECONDS")
                .help("Duration for IP blacklist")
                .default_value("600")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("node_discovery_interval")
                .long("discovery-interval")
                .value_name("SECONDS")
                .help("Interval for node discovery")
                .default_value("3600")
                .value_parser(value_parser!(u64)),
        )
        .get_matches();

    // Parse CLI args
    let address = *matches
        .get_one::<SocketAddr>("address")
        .expect("Address is required");

    let prefix_hex = matches.get_one::<String>("prefix").unwrap();
    let prefix_bits = u64::from_str_radix(prefix_hex, 16).expect("Invalid prefix hex");
    let prefix_bit_length = (prefix_hex.len() * 4) as u8;
    let prefix = RoutingPrefix::new(prefix_bit_length, prefix_bits);

    let bootstrap_nodes: Vec<SocketAddr> = matches
        .get_one::<String>("bootstrap_nodes")
        .unwrap()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().expect("Invalid bootstrap node address"))
        .collect();

    let pow_difficulty = *matches
        .get_one::<usize>("pow_difficulty")
        .expect("PoW difficulty is required");

    let max_ttl = *matches
        .get_one::<u64>("max_ttl")
        .expect("Max TTL is required");

    let min_argon2_params = SerializableArgon2Params {
        m_cost: *matches
            .get_one::<u32>("min_m_cost")
            .expect("min_m_cost is required"),
        t_cost: *matches
            .get_one::<u32>("min_t_cost")
            .expect("min_t_cost is required"),
        p_cost: *matches
            .get_one::<u32>("min_p_cost")
            .expect("min_p_cost is required"),
        output_length: Some(32),
    };

    let cleanup_interval =
        Duration::from_secs(*matches.get_one::<u64>("cleanup_interval").expect("required"));
    let blacklist_duration =
        Duration::from_secs(*matches.get_one::<u64>("blacklist_duration").expect("required"));
    let node_discovery_interval = Duration::from_secs(
        *matches
            .get_one::<u64>("node_discovery_interval")
            .expect("required"),
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
    )
    .await;

    // Keep running
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
