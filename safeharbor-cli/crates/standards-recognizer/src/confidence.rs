pub const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.95;

pub fn high_confidence(confidence: f64) -> bool {
    confidence >= HIGH_CONFIDENCE_THRESHOLD
}

pub fn max_confidence(values: impl IntoIterator<Item = f64>) -> f64 {
    values.into_iter().fold(0.0_f64, f64::max)
}
