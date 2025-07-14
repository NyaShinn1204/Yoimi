import re
import os
import time
import logging

from typing import Iterator


def path_check(input_path):
    invalid_chars = r'[<>:"|?*]'
    if re.search(invalid_chars, input_path):
        return False

    if not input_path.strip():
        return False

    has_extension = bool(os.path.splitext(input_path)[1])
    looks_like_path = '/' in input_path or '\\' in input_path

    return has_extension or looks_like_path

class Logger:
    COLOR_GREEN = "\033[92m"
    COLOR_GRAY = "\033[90m"
    COLOR_RESET = "\033[0m"
    COLOR_BLUE = "\033[94m"
    class CustomFormatter(logging.Formatter):
        def format(self, record):
            service_name = getattr(record, "service_name", "")
            levelname = record.levelname
            record.color_service_name = f"{Logger.COLOR_BLUE}{service_name}{Logger.COLOR_RESET}" if service_name else ""
            record.color_levelname = f"{Logger.COLOR_GRAY}{levelname}{Logger.COLOR_RESET}"
            
            if not hasattr(record, "asctime"):
                record.asctime = self.formatTime(record, self.datefmt)
            record.color_asctime = f"{Logger.COLOR_GREEN}{record.asctime}{Logger.COLOR_RESET}"
    
            self._style._fmt = (
                "%(color_asctime)s [%(color_levelname)s] %(color_service_name)s : %(message)s"
            )
            return super().format(record)
    
    class ServiceLoggerAdapter(logging.LoggerAdapter):
        def process(self, msg, kwargs):
            kwargs.setdefault('extra', {})
            kwargs['extra'].setdefault('service_name', self.extra['service_name'])
            return msg, kwargs
    
    def create_logger(service_name: str, LOG_LEVEL: bool):
        base_logger = logging.getLogger('YoimiLogger')
        if LOG_LEVEL == "DEBUG":
            base_logger.setLevel(logging.DEBUG)
        else:
            base_logger.setLevel(logging.INFO)
    
        formatter = Logger.CustomFormatter(
            '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
    
        if not base_logger.handlers:
            base_logger.addHandler(console_handler)
        
        logger = Logger.ServiceLoggerAdapter(base_logger, {'service_name': service_name})
        return logger

def download_command(input: str, command_list: Iterator):
    pass