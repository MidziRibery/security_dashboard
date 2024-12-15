### helpers/utils.py - Utility Functions and Shared Logic

import platform
from typing import List
import pandas as pd
import numpy as np

def get_windows_if_list():
    """Get the list of network interfaces on Windows"""
    if platform.system() != "Windows":
        raise NotImplementedError("get_windows_if_list is only available on Windows")
    from scapy.arch.windows import get_windows_if_list
    return get_windows_if_list()

def calculate_entropy(values: List) -> float:
    """Calculate Shannon entropy for a list of values"""
    if not values:
        return 0.0
    value_counts = pd.Series(values).value_counts(normalize=True)
    return -(value_counts * np.log2(value_counts)).sum()

def normalize_data(data: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Normalize specified columns in a DataFrame"""
    normalized_data = data.copy()
    for column in columns:
        if column in normalized_data:
            col_min = normalized_data[column].min()
            col_max = normalized_data[column].max()
            normalized_data[column] = (normalized_data[column] - col_min) / (col_max - col_min)
    return normalized_data
