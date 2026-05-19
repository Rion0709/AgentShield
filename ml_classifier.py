# agentshield/ml_classifier.py
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from .logger import security_logger
except ImportError:
    from logger import security_logger

class MLInjectionDetector:
    """Machine learning based prompt injection classifier using TF-IDF + Logistic Regression."""
    
    def __init__(self):
        self.is_supported = HAS_SKLEARN
        self.is_trained = False
        if not self.is_supported:
            security_logger.warning("scikit-learn is not installed. ML Classifier remains disabled. Install it using 'pip install scikit-learn'.")
            self.vectorizer = None
            self.classifier = None
        else:
            self.vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
            self.classifier = LogisticRegression(C=1.0)

    def train(self, safe_prompts: list, harmful_prompts: list) -> bool:
        """Trains the ML model on provided lists of safe and harmful prompts."""
        if not self.is_supported:
            security_logger.error("Cannot train ML Classifier: scikit-learn is missing.")
            return False
            
        try:
            texts = safe_prompts + harmful_prompts
            labels = [0] * len(safe_prompts) + [1] * len(harmful_prompts)
            
            X = self.vectorizer.fit_transform(texts)
            self.classifier.fit(X, labels)
            self.is_trained = True
            security_logger.info(f"ML Classifier trained successfully with {len(texts)} total samples.")
            return True
        except Exception as e:
            security_logger.error(f"ML Classifier training failed: {e}")
            return False

    def predict(self, prompt: str) -> dict:
        """Predicts probability of a prompt injection attack. Returns: {'is_harmful': bool, 'confidence': float}"""
        if not self.is_supported or not self.is_trained:
            return {"is_harmful": False, "confidence": 0.0}
            
        try:
            X = self.vectorizer.transform([prompt])
            prob = self.classifier.predict_proba(X)[0][1]
            return {
                "is_harmful": prob > 0.75,  # 75% confidence threshold for classification
                "confidence": float(prob)
            }
        except Exception as e:
            security_logger.error(f"ML prediction error: {e}")
            return {"is_harmful": False, "confidence": 0.0}
