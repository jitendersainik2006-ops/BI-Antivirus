"""
BI Antivirus - Local Machine Learning Inference Engine
Provides safe, explainable, on-device machine-learning static PE classification.
Features:
- Multi-dimensional feature vector extraction (12 normalized static PE features).
- Calibrated probabilistic inference (Logistic Sigmoid decision function).
- Explainable classification: probability score (0.0 to 1.0), verdict, confidence, and top feature contributions.
- Cryptographic model versioning: HMAC-SHA256 model manifest integrity verification.
- Anti-tampering & Safe Rollback: Reverts to verified factory baseline model if an update fails validation.
- Zero external cloud dependencies: Runs 100% locally and memory-safe without executing inspected binaries.
"""

import os
import math
import json
import hmac
import hashlib
import time
import logging
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple

from bi_antivirus.config import DATA_DIR
from bi_antivirus.core.pe_classifier import PEClassifier

logger = logging.getLogger("BI_MLEngine")

DEFAULT_MODEL_DIR = DATA_DIR / "models"
MODEL_HMAC_KEY = b"BI_LOCAL_ML_INTEGRITY_SALT_2026_SECURE"

# Factory Baseline Model Weights (Calibrated for static PE detection)
BASELINE_MODEL_V1 = {
    "model_id": "BI-ML-PE-BASELINE-V1",
    "version": 1,
    "model_type": "LOGISTIC_FEATURE_CLASSIFIER",
    "created_at": 1729000000.0,
    "bias": -2.80,
    "thresholds": {
        "malicious": 0.75,
        "suspicious": 0.45,
    },
    "feature_weights": {
        "entropy_total": 2.20,
        "max_section_entropy": 2.50,
        "section_count": 0.80,
        "raw_virtual_discrepancy": 1.60,
        "rwx_section_count": 3.80,
        "packer_section_flag": 3.20,
        "missing_mitigations_score": 1.40,
        "injection_api_weight": 2.90,
        "c2_network_api_weight": 1.80,
        "ransomware_crypto_api_weight": 2.40,
        "overlay_flag": 1.10,
        "signed_authenticode_flag": -2.50,  # Negative weight suppresses false positives on signed binaries
    },
    "description": "Factory baseline static PE classification model trained on benign Windows binaries and malicious samples.",
}


@dataclass
class MLPrediction:
    """Output prediction record from local ML inference."""
    probability: float
    verdict: str  # BENIGN, SUSPICIOUS, MALICIOUS
    confidence: float
    model_version: int
    model_id: str
    feature_vector: Dict[str, float]
    top_contributing_features: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FeatureExtractor:
    """Extracts normalized 12-dimensional numerical feature vectors from Windows binaries."""

    def __init__(self, pe_classifier: Optional[PEClassifier] = None):
        self.pe_classifier = pe_classifier or PEClassifier()

    def extract_features(
        self,
        file_path: Optional[Path] = None,
        data: Optional[bytes] = None,
        pe_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """
        Extract normalized numerical features (bounded to roughly [-1.0, 1.0] or [0.0, 1.0]).
        """
        if pe_info is None:
            if file_path and Path(file_path).exists():
                pe_info = self.pe_classifier.analyze_file(Path(file_path))
            elif data:
                pe_info = self.pe_classifier.analyze_bytes(data)
            else:
                return self._empty_feature_vector()

        if not pe_info.get("is_pe", False):
            # Not a PE binary: return neutral zero vector
            return self._empty_feature_vector()

        # 1. Entropy features
        entropy_total = min(max(pe_info.get("overall_entropy", 0.0) / 8.0, 0.0), 1.0)

        sections = pe_info.get("sections", [])
        section_entropies = [s.get("entropy", 0.0) for s in sections] if sections else [0.0]
        max_sec_entropy = min(max(max(section_entropies) / 8.0, 0.0), 1.0) if section_entropies else 0.0

        # 2. Structural anomalies
        sec_count = min(max(len(sections) / 15.0, 0.0), 1.0)

        # Raw vs Virtual size discrepancy
        raw_sizes = sum(s.get("raw_size", 0) for s in sections)
        virt_sizes = sum(s.get("virtual_size", 0) for s in sections)
        discrepancy = 0.0
        if virt_sizes > 0 and raw_sizes > 0:
            ratio = abs(virt_sizes - raw_sizes) / max(virt_sizes, raw_sizes)
            discrepancy = min(ratio, 1.0)

        # 3. Permissions & Section names
        rwx_count = sum(1 for s in sections if s.get("is_rwx", False))
        rwx_norm = min(rwx_count / 3.0, 1.0)

        packer_flag = 1.0 if pe_info.get("has_packer_sections", False) else 0.0

        # 4. Exploit Mitigations
        mitigations = pe_info.get("mitigations", {})
        missing_count = 0
        if not mitigations.get("dep", False):
            missing_count += 1
        if not mitigations.get("aslr", False):
            missing_count += 1
        if not mitigations.get("cfg", False):
            missing_count += 1
        missing_mitigations_norm = missing_count / 3.0

        # 5. Suspicious API categories
        api_cat = pe_info.get("suspicious_apis_by_category", {})
        injection_apis = len(api_cat.get("PROCESS_INJECTION", []))
        c2_apis = len(api_cat.get("NETWORK_C2", []))
        crypto_apis = len(api_cat.get("RANSOMWARE_CRYPTO", []))

        injection_norm = min(injection_apis / 4.0, 1.0)
        c2_norm = min(c2_apis / 3.0, 1.0)
        crypto_norm = min(crypto_apis / 3.0, 1.0)

        # 6. Overlay & Digital Signature
        overlay_flag = 1.0 if pe_info.get("has_overlay", False) else 0.0

        # Authenticode signature presence
        has_auth = pe_info.get("data_directories", {}).get("SECURITY", {}).get("present", False)
        signed_flag = 1.0 if has_auth else 0.0

        return {
            "entropy_total": round(entropy_total, 4),
            "max_section_entropy": round(max_sec_entropy, 4),
            "section_count": round(sec_count, 4),
            "raw_virtual_discrepancy": round(discrepancy, 4),
            "rwx_section_count": round(rwx_norm, 4),
            "packer_section_flag": round(packer_flag, 4),
            "missing_mitigations_score": round(missing_mitigations_norm, 4),
            "injection_api_weight": round(injection_norm, 4),
            "c2_network_api_weight": round(c2_norm, 4),
            "ransomware_crypto_api_weight": round(crypto_norm, 4),
            "overlay_flag": round(overlay_flag, 4),
            "signed_authenticode_flag": round(signed_flag, 4),
        }

    def _empty_feature_vector(self) -> Dict[str, float]:
        """Return zeroed feature vector for non-PE files."""
        return {
            "entropy_total": 0.0,
            "max_section_entropy": 0.0,
            "section_count": 0.0,
            "raw_virtual_discrepancy": 0.0,
            "rwx_section_count": 0.0,
            "packer_section_flag": 0.0,
            "missing_mitigations_score": 0.0,
            "injection_api_weight": 0.0,
            "c2_network_api_weight": 0.0,
            "ransomware_crypto_api_weight": 0.0,
            "overlay_flag": 0.0,
            "signed_authenticode_flag": 0.0,
        }


class LocalMLEngine:
    """Local, explainable machine-learning inference engine with cryptographic model versioning."""

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        signing_key: Optional[bytes] = None,
    ):
        self.model_dir = Path(model_dir or DEFAULT_MODEL_DIR)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.signing_key = signing_key or MODEL_HMAC_KEY
        self.extractor = FeatureExtractor()

        self._active_model: Dict[str, Any] = dict(BASELINE_MODEL_V1)
        self._fallback_baseline: Dict[str, Any] = dict(BASELINE_MODEL_V1)

        # Try to load latest verified model on disk, or initialize baseline
        self.active_model_path = self.model_dir / "active_model.json"
        self._load_or_initialize_model()

    def _compute_model_signature(self, model_dict: Dict[str, Any]) -> str:
        """Compute HMAC-SHA256 signature over canonical model manifest."""
        data_to_sign = {k: v for k, v in model_dict.items() if k != "hmac_signature"}
        canonical = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":"))
        return hmac.new(self.signing_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _load_or_initialize_model(self) -> None:
        """Load persisted model or write signed baseline model."""
        if self.active_model_path.exists():
            try:
                content = json.loads(self.active_model_path.read_text(encoding="utf-8"))
                sig = content.get("hmac_signature")
                expected = self._compute_model_signature(content)
                if sig and hmac.compare_digest(sig, expected):
                    self._active_model = content
                    logger.info(f"Loaded verified ML model: {content.get('model_id')} (v{content.get('version')})")
                    return
                else:
                    logger.warning("ML model signature tampered! Reverting to factory baseline model.")
            except Exception as e:
                logger.error(f"Failed loading ML model from disk: {e}")

        # Fallback to signed baseline model
        baseline_copy = dict(self._fallback_baseline)
        baseline_copy["hmac_signature"] = self._compute_model_signature(baseline_copy)
        self._active_model = baseline_copy
        try:
            self.active_model_path.write_text(json.dumps(baseline_copy, indent=2), encoding="utf-8")
        except Exception:
            pass

    @property
    def model_version(self) -> int:
        return int(self._active_model.get("version", 1))

    @property
    def model_id(self) -> str:
        return str(self._active_model.get("model_id", "UNKNOWN"))

    def predict(
        self,
        file_path: Optional[Path] = None,
        data: Optional[bytes] = None,
        pe_info: Optional[Dict[str, Any]] = None,
    ) -> MLPrediction:
        """
        Execute safe local ML inference on binary features.
        Returns: MLPrediction with probability, verdict, confidence, and explainability factors.
        """
        features = self.extractor.extract_features(file_path=file_path, data=data, pe_info=pe_info)

        # Non-PE binary check
        if all(v == 0.0 for v in features.values()):
            return MLPrediction(
                probability=0.01,
                verdict="BENIGN",
                confidence=0.99,
                model_version=self.model_version,
                model_id=self.model_id,
                feature_vector=features,
                top_contributing_features=[],
            )

        bias = float(self._active_model.get("bias", -2.80))
        weights = self._active_model.get("feature_weights", {})
        thresholds = self._active_model.get("thresholds", {"malicious": 0.75, "suspicious": 0.45})

        z = bias
        contributions = []

        for feat_name, val in features.items():
            w = float(weights.get(feat_name, 0.0))
            contrib = w * val
            z += contrib
            if abs(contrib) > 0.05:
                contributions.append({
                    "feature": feat_name,
                    "value": val,
                    "weight": w,
                    "contribution": round(contrib, 4),
                })

        # Logistic Sigmoid function
        prob = 1.0 / (1.0 + math.exp(-max(min(z, 20.0), -20.0)))
        prob = round(prob, 4)

        # Verdict assignment
        if prob >= thresholds.get("malicious", 0.75):
            verdict = "MALICIOUS"
            confidence = round(prob, 4)
        elif prob >= thresholds.get("suspicious", 0.45):
            verdict = "SUSPICIOUS"
            confidence = round(1.0 - abs(prob - 0.60) / 0.60, 4)
        else:
            verdict = "BENIGN"
            confidence = round(1.0 - prob, 4)

        # Sort top positive contributions
        contributions.sort(key=lambda x: x["contribution"], reverse=True)

        return MLPrediction(
            probability=prob,
            verdict=verdict,
            confidence=confidence,
            model_version=self.model_version,
            model_id=self.model_id,
            feature_vector=features,
            top_contributing_features=contributions[:5],
        )

    def update_model(self, new_model_bundle: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Deploy an updated ML model bundle:
        Enforces monotonic version check (v_new > v_current) and HMAC signature verification.
        """
        incoming_version = int(new_model_bundle.get("version", 0))
        current_version = self.model_version

        if incoming_version <= current_version:
            return False, f"Anti-rollback rejection: incoming model version ({incoming_version}) <= active version ({current_version})"

        sig = new_model_bundle.get("hmac_signature", "")
        expected = self._compute_model_signature(new_model_bundle)
        if not hmac.compare_digest(sig, expected):
            return False, "Model bundle integrity check failed: HMAC signature mismatch"

        # Backup current model before upgrading
        backup_path = self.model_dir / f"model_backup_v{current_version}.json"
        try:
            backup_path.write_text(json.dumps(self._active_model, indent=2), encoding="utf-8")
            self._active_model = dict(new_model_bundle)
            self.active_model_path.write_text(json.dumps(self._active_model, indent=2), encoding="utf-8")
            logger.info(f"Upgraded ML model to v{incoming_version} ({self._active_model.get('model_id')})")
            return True, f"Successfully upgraded ML model to v{incoming_version}"
        except Exception as e:
            logger.error(f"Failed persisting upgraded ML model: {e}")
            return False, f"Persistence error: {e}"

    def rollback_model(self) -> Tuple[bool, str]:
        """
        Emergency model rollback: Reverts to factory baseline model (v1).
        """
        baseline = dict(self._fallback_baseline)
        baseline["hmac_signature"] = self._compute_model_signature(baseline)
        self._active_model = baseline
        try:
            self.active_model_path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
            logger.warning("Rolled back ML model to factory baseline v1.")
            return True, "Successfully rolled back ML model to factory baseline v1"
        except Exception as e:
            logger.error(f"Failed persisting rollback model: {e}")
            return False, f"Rollback persistence error: {e}"

    def evaluate_corpus(self, samples: List[Tuple[Any, str]]) -> Dict[str, Any]:
        """
        Evaluate classification metrics on a labeled test corpus.
        samples: list of (sample_input, ground_truth_label) where ground_truth is 'BENIGN' or 'MALICIOUS'.
        Returns: confusion matrix, precision, recall, false positive rate, accuracy.
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for pe_data, ground_truth in samples:
            gt = ground_truth.upper().strip()
            if isinstance(pe_data, dict):
                pred = self.predict(pe_info=pe_data)
            elif isinstance(pe_data, bytes):
                pred = self.predict(data=pe_data)
            elif isinstance(pe_data, Path):
                pred = self.predict(file_path=pe_data)
            else:
                pred = self.predict(data=str(pe_data).encode("utf-8"))

            is_mal = pred.verdict in ("MALICIOUS", "SUSPICIOUS")

            if gt == "MALICIOUS":
                if is_mal:
                    tp += 1
                else:
                    fn += 1
            else:
                if is_mal:
                    fp += 1
                else:
                    tn += 1

        total = tp + fp + tn + fn
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        accuracy = round((tp + tn) / total, 4) if total > 0 else 1.0

        return {
            "total_samples": total,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "confusion_matrix": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
            },
            "precision": precision,
            "recall": recall,
            "false_positive_rate": fpr,
            "accuracy": accuracy,
            "model_version": self.model_version,
            "model_id": self.model_id,
        }
