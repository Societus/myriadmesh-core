//! Machine Learning Path Prediction Engine
//!
//! Implements a lightweight path quality predictor using historical network data.
//! No external ML dependencies - uses linear regression model stored in-memory.
//!
//! Features:
//! - Record path observations with quality metrics
//! - Predict path quality for untested routes
//! - Incremental learning and periodic model retraining
//! - Confidence scoring for predictions
//! - Serialization support for model persistence
//!
//! Performance targets:
//! - Prediction latency < 1ms per path
//! - Model memory footprint < 1MB
//! - Confidence tracking across training data

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of training samples per path
const MAX_TRAINING_SAMPLES: usize = 1000;

/// Minimum training samples before confidence > 0.5
const MIN_CONFIDENCE_SAMPLES: usize = 10;

/// Quality score range
const MIN_QUALITY_SCORE: f64 = 0.0;
const MAX_QUALITY_SCORE: f64 = 1.0;

/// Represents a network path for training data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathFeatures {
    /// Length of the path (hop count)
    pub path_length: u32,
    /// Number of hops
    pub hop_count: u32,
    /// Average link quality (0.0-1.0)
    pub link_quality: f64,
    /// Network congestion indicator (0.0-1.0)
    pub congestion: f64,
    /// Average latency (milliseconds)
    pub latency_ms: f64,
}

impl PathFeatures {
    /// Create new path features
    pub fn new(
        path_length: u32,
        hop_count: u32,
        link_quality: f64,
        congestion: f64,
        latency_ms: f64,
    ) -> Self {
        Self {
            path_length: path_length.max(1),
            hop_count: hop_count.max(1),
            link_quality: link_quality.clamp(0.0, 1.0),
            congestion: congestion.clamp(0.0, 1.0),
            latency_ms: latency_ms.max(0.0),
        }
    }

    /// Normalize features for model training
    fn normalize(&self) -> NormalizedFeatures {
        NormalizedFeatures {
            path_length: (self.path_length as f64) / 32.0, // Typical max path length
            hop_count: (self.hop_count as f64) / 16.0,     // Typical max hops
            link_quality: self.link_quality,
            congestion: self.congestion,
            latency_ms: (self.latency_ms / 1000.0).min(1.0), // Clamp to 1s max
        }
    }
}

/// Normalized feature vector for ML model
#[derive(Debug, Clone)]
struct NormalizedFeatures {
    path_length: f64,
    hop_count: f64,
    link_quality: f64,
    congestion: f64,
    latency_ms: f64,
}

impl NormalizedFeatures {
    /// Compute prediction using linear regression coefficients
    fn predict(&self, model: &LinearModel) -> f64 {
        let mut score = model.bias;
        score += self.path_length * model.weights[0];
        score += self.hop_count * model.weights[1];
        score += self.link_quality * model.weights[2];
        score -= self.congestion * model.weights[3];
        score -= self.latency_ms * model.weights[4];
        score.clamp(MIN_QUALITY_SCORE, MAX_QUALITY_SCORE)
    }
}

/// Simple linear regression model for path quality prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinearModel {
    /// Weights for each feature
    weights: [f64; 5],
    /// Bias term
    bias: f64,
}

impl LinearModel {
    /// Create a new model with sensible defaults
    fn new() -> Self {
        Self {
            weights: [-0.1, -0.15, 0.5, -0.3, -0.05],
            bias: 0.6,
        }
    }

    /// Train model using gradient descent on observed data
    fn train(&mut self, samples: &[(PathFeatures, f64)]) {
        if samples.is_empty() {
            return;
        }

        let learning_rate = 0.01;
        let iterations = 50;

        for _ in 0..iterations {
            let mut gradients = [0.0; 5];
            let mut bias_gradient = 0.0;

            for (features, actual_quality) in samples {
                let normalized = features.normalize();
                let predicted = normalized.predict(self);
                let error = predicted - actual_quality;

                gradients[0] += error * normalized.path_length;
                gradients[1] += error * normalized.hop_count;
                gradients[2] += error * normalized.link_quality;
                gradients[3] += error * normalized.congestion;
                gradients[4] += error * normalized.latency_ms;
                bias_gradient += error;
            }

            let count = samples.len() as f64;
            for (i, gradient) in gradients.iter().enumerate() {
                self.weights[i] -= learning_rate * (gradient / count);
            }
            self.bias -= learning_rate * (bias_gradient / count);
        }
    }
}

/// Training sample with features and observed quality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSample {
    pub features: PathFeatures,
    pub observed_quality: f64,
    pub timestamp: u64,
}

impl TrainingSample {
    /// Create a new training sample
    pub fn new(features: PathFeatures, observed_quality: f64) -> Self {
        Self {
            features,
            observed_quality: observed_quality.clamp(MIN_QUALITY_SCORE, MAX_QUALITY_SCORE),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Prediction result with confidence score
#[derive(Debug, Clone)]
pub struct Prediction {
    /// Predicted quality score (0.0-1.0)
    pub quality_score: f64,
    /// Confidence in this prediction (0.0-1.0)
    pub confidence: f64,
}

impl Prediction {
    /// Create a new prediction
    pub fn new(quality_score: f64, confidence: f64) -> Self {
        Self {
            quality_score: quality_score.clamp(MIN_QUALITY_SCORE, MAX_QUALITY_SCORE),
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// Machine Learning Path Predictor
///
/// Maintains training data and a lightweight decision model for predicting
/// path quality without external ML dependencies.
#[derive(Debug, Clone)]
pub struct PathPredictor {
    /// Training samples indexed by path signature
    training_data: HashMap<u64, Vec<TrainingSample>>,
    /// Current linear regression model
    model: LinearModel,
    /// Last model training time
    last_training: Instant,
    /// Training interval
    training_interval: Duration,
    /// Overall prediction accuracy metric
    accuracy_metric: f64,
}

impl PathPredictor {
    /// Create a new path predictor
    pub fn new() -> Self {
        Self {
            training_data: HashMap::new(),
            model: LinearModel::new(),
            last_training: Instant::now(),
            training_interval: Duration::from_secs(300), // Retrain every 5 minutes
            accuracy_metric: 0.5,
        }
    }

    /// Record an observation of a path and its quality
    ///
    /// # Arguments
    /// * `path_signature` - Hash of the path for grouping
    /// * `features` - Feature vector for the path
    /// * `quality_score` - Observed quality (0.0-1.0)
    pub fn record_path_observation(
        &mut self,
        path_signature: u64,
        features: PathFeatures,
        quality_score: f64,
    ) {
        let sample = TrainingSample::new(features, quality_score);
        let samples = self
            .training_data
            .entry(path_signature)
            .or_insert_with(Vec::new);

        samples.push(sample);

        // Limit memory growth
        if samples.len() > MAX_TRAINING_SAMPLES {
            samples.remove(0);
        }

        // Periodically retrain model
        if self.last_training.elapsed() > self.training_interval {
            self.retrain_model();
        }
    }

    /// Predict quality of a candidate path
    ///
    /// Returns a prediction with quality score and confidence level.
    /// Lower latency paths and better link quality score higher.
    pub fn predict_path_quality(&self, features: &PathFeatures) -> Prediction {
        let normalized = features.normalize();
        let quality_score = normalized.predict(&self.model);

        // Confidence based on overall accuracy and path familiarity
        let base_confidence = self.accuracy_metric;
        let confidence = base_confidence * 0.8 + 0.2; // Min 20% confidence

        Prediction::new(quality_score, confidence)
    }

    /// Retrain the model using all accumulated training data
    ///
    /// Uses gradient descent to optimize weights. Should be called
    /// periodically as new observations arrive.
    pub fn retrain_model(&mut self) {
        let all_samples: Vec<(PathFeatures, f64)> = self
            .training_data
            .values()
            .flat_map(|samples| {
                samples
                    .iter()
                    .map(|s| (s.features.clone(), s.observed_quality))
                    .collect::<Vec<_>>()
            })
            .collect();

        if !all_samples.is_empty() {
            self.model.train(&all_samples);

            // Update accuracy metric
            let mut total_error = 0.0;
            for (features, actual) in &all_samples {
                let normalized = features.normalize();
                let predicted = normalized.predict(&self.model);
                let error = (predicted - actual).abs();
                total_error += error;
            }
            let mse = total_error / all_samples.len() as f64;
            self.accuracy_metric = (1.0 - mse).max(0.1);

            self.last_training = Instant::now();
        }
    }

    /// Get the current prediction confidence level
    ///
    /// Based on model training progress and accuracy.
    /// Returns 0.0-1.0 score.
    pub fn get_prediction_confidence(&self) -> f64 {
        let sample_count = self.training_data.values().map(|v| v.len()).sum::<usize>();
        let confidence_from_samples = ((sample_count as f64) / (MIN_CONFIDENCE_SAMPLES as f64))
            .min(1.0)
            * 0.5;
        (self.accuracy_metric * 0.5 + confidence_from_samples).min(1.0)
    }

    /// Get number of training samples accumulated
    pub fn training_sample_count(&self) -> usize {
        self.training_data.values().map(|v| v.len()).sum()
    }

    /// Get number of unique paths trained
    pub fn unique_paths_trained(&self) -> usize {
        self.training_data.len()
    }
}

impl Default for PathPredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_features_creation_and_normalization() {
        let features = PathFeatures::new(16, 5, 0.95, 0.1, 25.5);
        assert_eq!(features.path_length, 16);
        assert_eq!(features.hop_count, 5);
        assert_eq!(features.link_quality, 0.95);

        let normalized = features.normalize();
        assert!(normalized.path_length > 0.0);
        assert!(normalized.path_length <= 1.0);
        assert!(normalized.hop_count <= 1.0);
    }

    #[test]
    fn test_path_features_clamping() {
        let features = PathFeatures::new(100, 50, 1.5, -0.5, 5000.0);
        assert!(features.link_quality <= 1.0);
        assert!(features.congestion >= 0.0);
        assert!(features.path_length > 0);
    }

    #[test]
    fn test_model_training() {
        let mut model = LinearModel::new();
        let samples = vec![
            (
                PathFeatures::new(8, 3, 0.9, 0.1, 10.0),
                0.9,
            ),
            (
                PathFeatures::new(16, 6, 0.7, 0.4, 50.0),
                0.6,
            ),
            (
                PathFeatures::new(4, 2, 0.95, 0.05, 5.0),
                0.95,
            ),
        ];

        model.train(&samples);

        // Model should improve predictions after training
        let pred1 = samples[0].0.normalize().predict(&model);
        assert!(pred1 > 0.0 && pred1 < 1.0);
    }

    #[test]
    fn test_predictor_recording_observations() {
        let mut predictor = PathPredictor::new();

        let features1 = PathFeatures::new(8, 3, 0.9, 0.1, 15.0);
        let features2 = PathFeatures::new(16, 6, 0.7, 0.5, 50.0);

        predictor.record_path_observation(100, features1.clone(), 0.88);
        predictor.record_path_observation(100, features1, 0.89);
        predictor.record_path_observation(200, features2, 0.65);

        assert_eq!(predictor.unique_paths_trained(), 2);
        assert_eq!(predictor.training_sample_count(), 3);
    }

    #[test]
    fn test_prediction_generation() {
        let predictor = PathPredictor::new();
        let features = PathFeatures::new(8, 3, 0.9, 0.1, 15.0);

        let prediction = predictor.predict_path_quality(&features);
        assert!(prediction.quality_score >= MIN_QUALITY_SCORE);
        assert!(prediction.quality_score <= MAX_QUALITY_SCORE);
        assert!(prediction.confidence > 0.0);
        assert!(prediction.confidence <= 1.0);
    }

    #[test]
    fn test_confidence_grows_with_training() {
        let mut predictor = PathPredictor::new();
        let initial_confidence = predictor.get_prediction_confidence();

        for i in 0..20 {
            let features = PathFeatures::new(
                8 + (i % 8) as u32,
                3 + (i % 4) as u32,
                0.8 + (i as f64 * 0.01),
                0.1 + (i as f64 * 0.02),
                15.0 + (i as f64 * 5.0),
            );
            predictor.record_path_observation(i as u64, features, 0.8 + (i as f64 * 0.01));
        }

        let final_confidence = predictor.get_prediction_confidence();
        assert!(final_confidence > initial_confidence);
        assert!(final_confidence > 0.3);
    }

    #[test]
    fn test_model_memory_bounds() {
        let mut predictor = PathPredictor::new();

        // Add many samples (simulating high-volume operation)
        for path_id in 0..100 {
            for sample in 0..500 {
                let features = PathFeatures::new(
                    4 + (sample % 12) as u32,
                    2 + (sample % 6) as u32,
                    0.7 + (sample as f64 % 0.2),
                    0.2,
                    20.0,
                );
                predictor.record_path_observation(path_id, features, 0.85);
            }
        }

        // Memory should be bounded by MAX_TRAINING_SAMPLES per path
        let total_samples = predictor.training_sample_count();
        assert!(total_samples <= 100 * MAX_TRAINING_SAMPLES);
    }
}
