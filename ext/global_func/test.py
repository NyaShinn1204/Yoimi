import logging
import niconico as comment

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"
test = comment.global_comment()


class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)

        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{COLOR_BLUE}{record.service_name}{COLOR_RESET}"
            )

        log_message = log_message.replace(
            record.asctime, f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        )

        return log_message


logger = logging.getLogger("YoimiLogger")
LOG_LEVEL = "INFO"
if LOG_LEVEL == "DEBUG":
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

formatter = CustomFormatter(
    "%(asctime)s [%(levelname)s] %(service_name)s : %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)
config = {
    "directorys": {
        "Temp": "./temp",
        "Downloads": "./downloads",
        "Binaries": "./binaries",
        "Service_util": "./ext/utils/{servicename}_util",
    }
}
test.download_niconico_comment(
    logger,
    [False, False, True, True],
    "Unnamed Memory",
    "名も無き物語に終焉を",
    24,
    config,
    "Unnamed Memory_第24話_名も無き物語に終焉を",
    "TEST_APP",
)
