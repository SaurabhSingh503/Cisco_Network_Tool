# logging_helpers.py

import logging
from pathlib import Path
import sys

def setup_logging(level=logging.INFO, log_file="network_tool.log"):
    """
    Sets up logging for the application.
    Logs both to console and to a file.
    """
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # File handler
    file_handler = logging.FileHandler(log_dir / log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # Stream handler (console)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(level)

    logging.basicConfig(
        level=level,
        handlers=[file_handler, stream_handler]
    )

def get_logger(name):
    """
    Returns a logger with the given name.
    """
    return logging.getLogger(name)
