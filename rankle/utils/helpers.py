"""
Helper utilities for Rankle
"""

import json
from pathlib import Path
from typing import Any


def load_json_file(filepath: Path) -> dict[str, Any]:
    """
    Load JSON file

    Args:
        filepath: Path to JSON file

    Returns:
        Dictionary with JSON content
    """
    try:
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {filepath}: {e}")
        return {}


def save_json_file(data: dict[str, Any], filepath: Path, indent: int = 2) -> bool:
    """
    Save data to JSON file

    Args:
        data: Data to save
        filepath: Path to save file
        indent: JSON indentation level

    Returns:
        True if successful, False otherwise
    """
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving JSON file {filepath}: {e}")
        return False


def truncate_list(items: list[Any], max_items: int = 3, show_total: bool = True) -> str:
    """
    Truncate list for display

    Args:
        items: List of items
        max_items: Maximum items to show
        show_total: Show total count

    Returns:
        Formatted string
    """
    if not items:
        return "None"

    if len(items) <= max_items:
        return ", ".join(str(item) for item in items)

    shown = ", ".join(str(item) for item in items[:max_items])
    if show_total:
        remaining = len(items) - max_items
        return f"{shown} ... (+{remaining})"
    return shown


def format_bytes(bytes_value: float) -> str:  # Changed from int to float
    """
    Format bytes to human readable format

    Args:
        bytes_value: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(milliseconds: float) -> str:
    """
    Format duration to human readable format

    Args:
        milliseconds: Duration in milliseconds

    Returns:
        Formatted string (e.g., "123.45ms")
    """
    if milliseconds < 1000:
        return f"{milliseconds:.2f}ms"
    seconds = milliseconds / 1000
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = seconds / 60
    return f"{minutes:.2f}m"
