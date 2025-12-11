#![no_main]

use libfuzzer_sys::fuzz_target;
use myriadmesh_dht::routing_table::RoutingTable;
use myriadmesh_dht::node_info::NodeInfo;
use myriadmesh_protocol::types::NodeId;

fuzz_target!(|data: &[u8]| {
    // SECURITY P1.4.1: Fuzz DHT routing table operations
    // This test ensures DHT operations don't crash on malformed input

    // Create a dummy node ID for the local node
    let local_node_id = NodeId::from_bytes([1u8; 64]);
    let mut routing_table = RoutingTable::new(local_node_id);

    // Try to add arbitrary node IDs to the routing table
    if data.len() >= 64 {
        let mut node_id_bytes = [0u8; 64];
        node_id_bytes.copy_from_slice(&data[0..64]);
        let node_id = NodeId::from_bytes(node_id_bytes);

        // Create a minimal NodeInfo - should not panic on any input
        let node_info = NodeInfo::new(node_id);
        // Try to add node - should not panic
        let _ = routing_table.add_or_update(node_info);
    }

    // Test with size variations
    if data.len() >= 128 {
        let mut node_id_bytes = [0u8; 64];
        node_id_bytes.copy_from_slice(&data[64..128]);
        let node_id = NodeId::from_bytes(node_id_bytes);

        let node_info = NodeInfo::new(node_id);
        let _ = routing_table.add_or_update(node_info);
    }

    // Try lookups on arbitrary data
    if !data.is_empty() && data.len() <= 64 {
        let mut search_bytes = [0u8; 64];
        search_bytes[..data.len()].copy_from_slice(data);
        let search_id = NodeId::from_bytes(search_bytes);
        let _ = routing_table.find_node(&search_id);
    }
});
