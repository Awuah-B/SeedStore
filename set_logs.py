#! /usr/bin/env python3
import logging
import sys
from typing import Optional

def setup_logger(name: str, level: Optional[str]= None) -> logging.Logger:
    logger = logging.getLogger(name)
    log_level = level or 'INFO'     # default to INFO
    logger.setLevel(getattr(logging, log_level.upper()))

    formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S'
            )
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    logger.propagate = False

    return logger
