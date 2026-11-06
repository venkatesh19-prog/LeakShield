import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """Computes Shannon entropy: H(X) = -sum(P(x) * log2(P(x)))."""
    if not data:
        return 0.0
    length = len(data)
    frequencies = Counter(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in frequencies.values())
    return round(entropy, 3)

def is_high_entropy(data: str, threshold: float = 4.2) -> bool:
    return calculate_shannon_entropy(data) >= threshold
