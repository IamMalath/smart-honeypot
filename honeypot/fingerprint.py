"""Re-export tool fingerprinting from the classifier so other modules can
import it without pulling the full classifier surface."""
from analyzer.classifier import fingerprint_tool

__all__ = ["fingerprint_tool"]
