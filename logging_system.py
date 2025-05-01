# logging_system.py
import logging
import logging.handlers
import os
from pathlib import Path

# Ensure logs directory exists
log_dir = Path('logs')
log_dir.mkdir(exist_ok=True)

# Configure the root logger (or a named logger)
logger = logging.getLogger('encryption')
logger.setLevel(logging.INFO)

# Create a TimedRotatingFileHandler for daily log rotation
log_file = log_dir / 'activity.log'
handler = logging.handlers.TimedRotatingFileHandler(
    filename=log_file,
    when='midnight',      # rotate at midnight each day
    backupCount=7,        # keep one week of logs (adjust as needed)
    encoding='utf-8',
    utc=False             # use local time for timestamps
)

# Set formatter to include time, level, and message
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
logger.addHandler(handler)
