# agentshield/anomaly.py
import time
from collections import defaultdict

class AnomalyDetector:
    """Analyzes time-based query behavior to identify anomalous threat levels from a user."""
    
    def __init__(self, window_seconds: int = 60, threshold_score: float = 0.4, min_requests: int = 5):
        self.window_seconds = window_seconds
        self.threshold_score = threshold_score
        self.min_requests = min_requests
        # Maps user_id to list of tuples: (timestamp, threat_score)
        self.history = defaultdict(list)

    def log_event(self, user_id: str, threat_score: float) -> dict:
        """
        Logs a user query threat event and evaluates if the trend represents an anomaly.
        Returns: {'anomaly_detected': bool, 'average_threat': float, 'variance': float, 'reason': str}
        """
        now = time.time()
        
        # Record new query threat level
        self.history[user_id].append((now, threat_score))
        
        # Prune items older than window limit
        self.history[user_id] = [
            (t, score) for t, score in self.history[user_id] 
            if now - t < self.window_seconds
        ]
        
        events = self.history[user_id]
        if len(events) < self.min_requests:
            return {
                "anomaly_detected": False,
                "average_threat": sum(s for _, s in events) / len(events) if events else 0.0,
                "variance": 0.0,
                "reason": "Accumulating request history."
            }
            
        scores = [score for _, score in events]
        avg_threat = sum(scores) / len(scores)
        
        # Calculate variance
        variance = 0.0
        if len(scores) > 1:
            variance = sum((x - avg_threat) ** 2 for x in scores) / (len(scores) - 1)
            
        # Trigger an anomaly if threat baseline surpasses limit threshold
        anomaly_detected = avg_threat > self.threshold_score
        
        reason = "Normal usage behavior."
        if anomaly_detected:
            reason = f"User threat average ({avg_threat:.2f}) exceeds threshold ({self.threshold_score:.2f}) over {len(scores)} requests."
            
        return {
            "anomaly_detected": anomaly_detected,
            "average_threat": avg_threat,
            "variance": variance,
            "reason": reason
        }
