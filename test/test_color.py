import logging
import colorama

colorama.init()

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_BLUE = "\033[94m"
COLOR_RESET = "\033[0m"

class CustomFormatter(logging.Formatter):
    def format(self, record):
        record.asctime = self.formatTime(record, self.datefmt)
        record.levelname = f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        record.asctime = f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        record.service_name = f"{COLOR_BLUE}{getattr(record, 'service_name', '')}{COLOR_RESET}"
        return super().format(record)

formatter = CustomFormatter('%(asctime)s [%(levelname)s] %(service_name)s : %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("TestLogger")
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

logger = logging.LoggerAdapter(logger, {"service_name": "Hulu-jp"})
logger.error("Traceback has occurred")
