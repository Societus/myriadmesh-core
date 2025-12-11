//! Geographic Routing - Location-based path selection
//!
//! Implements geographic routing algorithms that use node location data
//! to make intelligent routing decisions. Nodes closer to the destination
//! are preferred to minimize hops and latency.

use myriadmesh_protocol::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Geographic coordinates (latitude, longitude)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinates {
    /// Latitude in degrees (-90 to 90)
    pub latitude: f64,
    /// Longitude in degrees (-180 to 180)
    pub longitude: f64,
    /// Altitude in meters (optional)
    pub altitude: Option<f64>,
}

impl GeoCoordinates {
    /// Create new coordinates
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            altitude: None,
        }
    }

    /// Create new coordinates with altitude
    pub fn with_altitude(latitude: f64, longitude: f64, altitude: f64) -> Self {
        Self {
            latitude,
            longitude,
            altitude: Some(altitude),
        }
    }

    /// Calculate Haversine distance to another point (in kilometers)
    pub fn distance_to(&self, other: &GeoCoordinates) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Calculate bearing to another point (in degrees, 0-360)
    pub fn bearing_to(&self, other: &GeoCoordinates) -> f64 {
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let y = delta_lon.sin() * lat2.cos();
        let x = lat1.cos() * lat2.sin() - lat1.sin() * lat2.cos() * delta_lon.cos();

        let bearing = y.atan2(x).to_degrees();
        (bearing + 360.0) % 360.0
    }

    /// Check if coordinates are valid
    pub fn is_valid(&self) -> bool {
        self.latitude >= -90.0
            && self.latitude <= 90.0
            && self.longitude >= -180.0
            && self.longitude <= 180.0
    }
}

/// Node location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLocation {
    pub node_id: NodeId,
    pub coordinates: GeoCoordinates,
    pub last_updated: u64, // Unix timestamp
    pub confidence: f32,   // 0.0-1.0, GPS accuracy indicator
}

/// Geographic routing table
pub struct GeoRoutingTable {
    /// Node locations
    locations: HashMap<NodeId, NodeLocation>,
    /// Location cache TTL (seconds)
    ttl: u64,
}

impl GeoRoutingTable {
    /// Create a new geographic routing table
    pub fn new(ttl: u64) -> Self {
        Self {
            locations: HashMap::new(),
            ttl,
        }
    }

    /// Update node location
    pub fn update_location(&mut self, location: NodeLocation) {
        self.locations.insert(location.node_id, location);
    }

    /// Get node location
    pub fn get_location(&self, node_id: &NodeId) -> Option<&NodeLocation> {
        self.locations.get(node_id)
    }

    /// Remove expired locations
    pub fn cleanup_expired(&mut self, current_time: u64) {
        self.locations
            .retain(|_, loc| current_time - loc.last_updated < self.ttl);
    }

    /// Find nearest nodes to a target location
    ///
    /// Returns a list of (node_id, distance_km) sorted by distance
    pub fn find_nearest_nodes(
        &self,
        target: &GeoCoordinates,
        max_results: usize,
    ) -> Vec<(NodeId, f64)> {
        let mut distances: Vec<(NodeId, f64)> = self
            .locations
            .values()
            .map(|loc| (loc.node_id, loc.coordinates.distance_to(target)))
            .collect();

        // Sort by distance (NaN-safe)
        distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        // Take only max_results
        distances.truncate(max_results);
        distances
    }

    /// Find nodes in a direction (bearing-based routing)
    ///
    /// Returns nodes that are in the general direction of the target bearing
    /// Tolerance is in degrees (e.g., 45.0 for ±45° from target bearing)
    pub fn find_nodes_in_direction(
        &self,
        from: &GeoCoordinates,
        target_bearing: f64,
        tolerance: f64,
        max_results: usize,
    ) -> Vec<(NodeId, f64, f64)> {
        let mut candidates: Vec<(NodeId, f64, f64)> = self
            .locations
            .values()
            .filter_map(|loc| {
                let bearing = from.bearing_to(&loc.coordinates);
                let distance = from.distance_to(&loc.coordinates);

                // Calculate angular difference
                let mut diff = (bearing - target_bearing).abs();
                if diff > 180.0 {
                    diff = 360.0 - diff;
                }

                if diff <= tolerance {
                    Some((loc.node_id, bearing, distance))
                } else {
                    None
                }
            })
            .collect();

        // Sort by distance (NaN-safe)
        candidates.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));

        // Take only max_results
        candidates.truncate(max_results);
        candidates
    }

    /// Calculate next hop for geographic greedy forwarding
    ///
    /// Selects the neighbor node that is closest to the destination
    pub fn greedy_next_hop(
        &self,
        current_pos: &GeoCoordinates,
        dest_pos: &GeoCoordinates,
        neighbors: &[NodeId],
    ) -> Option<(NodeId, f64)> {
        let mut best: Option<(NodeId, f64)> = None;
        let current_dist = current_pos.distance_to(dest_pos);

        for neighbor in neighbors {
            if let Some(neighbor_loc) = self.get_location(neighbor) {
                let neighbor_dist = neighbor_loc.coordinates.distance_to(dest_pos);

                // Greedy: only consider neighbors closer to destination
                if neighbor_dist < current_dist {
                    match &best {
                        None => best = Some((*neighbor, neighbor_dist)),
                        Some((_, best_dist)) => {
                            if neighbor_dist < *best_dist {
                                best = Some((*neighbor, neighbor_dist));
                            }
                        }
                    }
                }
            }
        }

        best
    }

    /// Get total number of known locations
    pub fn location_count(&self) -> usize {
        self.locations.len()
    }

    /// Check if we have location for a node
    pub fn has_location(&self, node_id: &NodeId) -> bool {
        self.locations.contains_key(node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_coordinates_distance() {
        // New York City
        let nyc = GeoCoordinates::new(40.7128, -74.0060);
        // Los Angeles
        let la = GeoCoordinates::new(34.0522, -118.2437);

        let distance = nyc.distance_to(&la);
        // Actual distance is ~3944 km
        assert!((distance - 3944.0).abs() < 50.0);
    }

    #[test]
    fn test_geo_coordinates_bearing() {
        // New York to Los Angeles should be roughly west (270°)
        let nyc = GeoCoordinates::new(40.7128, -74.0060);
        let la = GeoCoordinates::new(34.0522, -118.2437);

        let bearing = nyc.bearing_to(&la);
        // Should be around 270° (west)
        assert!(bearing > 250.0 && bearing < 290.0);
    }

    #[test]
    fn test_geo_coordinates_validity() {
        let valid = GeoCoordinates::new(40.0, -74.0);
        assert!(valid.is_valid());

        let invalid_lat = GeoCoordinates::new(100.0, -74.0);
        assert!(!invalid_lat.is_valid());

        let invalid_lon = GeoCoordinates::new(40.0, -200.0);
        assert!(!invalid_lon.is_valid());
    }

    #[test]
    fn test_geo_routing_table() {
        let mut table = GeoRoutingTable::new(3600);
        let node_id = NodeId::from_bytes([0u8; 64]);

        let location = NodeLocation {
            node_id,
            coordinates: GeoCoordinates::new(40.0, -74.0),
            last_updated: 1000,
            confidence: 0.95,
        };

        table.update_location(location);
        assert_eq!(table.location_count(), 1);
        assert!(table.has_location(&node_id));

        let retrieved = table.get_location(&node_id).unwrap();
        assert_eq!(retrieved.confidence, 0.95);
    }

    #[test]
    fn test_find_nearest_nodes() {
        let mut table = GeoRoutingTable::new(3600);

        // Add three cities with unique NodeIds
        let mut nyc_id = [0u8; 64];
        nyc_id[0] = 1;
        let nyc = NodeLocation {
            node_id: NodeId::from_bytes(nyc_id),
            coordinates: GeoCoordinates::new(40.7128, -74.0060),
            last_updated: 1000,
            confidence: 0.95,
        };

        let mut philly_id = [0u8; 64];
        philly_id[0] = 2;
        let philly = NodeLocation {
            node_id: NodeId::from_bytes(philly_id),
            coordinates: GeoCoordinates::new(39.9526, -75.1652),
            last_updated: 1000,
            confidence: 0.95,
        };

        let mut boston_id = [0u8; 64];
        boston_id[0] = 3;
        let boston = NodeLocation {
            node_id: NodeId::from_bytes(boston_id),
            coordinates: GeoCoordinates::new(42.3601, -71.0589),
            last_updated: 1000,
            confidence: 0.95,
        };

        table.update_location(nyc);
        table.update_location(philly);
        table.update_location(boston);

        // Find nearest to NYC
        let target = GeoCoordinates::new(40.7128, -74.0060);
        let nearest = table.find_nearest_nodes(&target, 2);

        assert_eq!(nearest.len(), 2);
        // First should be NYC itself (distance ~0)
        assert!(nearest[0].1 < 1.0);
    }

    #[test]
    fn test_nan_handling_in_sorting() {
        // Test that NaN values in distance calculations don't cause panics
        let mut table = GeoRoutingTable::new(3600);

        // Add a node with valid coordinates
        let mut valid_id = [0u8; 64];
        valid_id[0] = 1;
        let valid = NodeLocation {
            node_id: NodeId::from_bytes(valid_id),
            coordinates: GeoCoordinates::new(40.0, -74.0),
            last_updated: 1000,
            confidence: 0.95,
        };
        table.update_location(valid);

        // Add a node with coordinates that might produce NaN
        let mut invalid_id = [0u8; 64];
        invalid_id[0] = 2;
        let invalid = NodeLocation {
            node_id: NodeId::from_bytes(invalid_id),
            coordinates: GeoCoordinates::new(f64::NAN, f64::NAN),
            last_updated: 1000,
            confidence: 0.0,
        };
        table.update_location(invalid);

        // This should not panic even with NaN coordinates
        let target = GeoCoordinates::new(40.0, -74.0);
        let result = table.find_nearest_nodes(&target, 5);

        // Should return results without panicking
        assert!(!result.is_empty());
    }
}
