import logging
import os
import os.path

LOG_LEVEL = logging.DEBUG

class Logger:
    def __init__(self, name):

        if type(name) is not str:
            name = name.__class__.__name__

        self._logger = logging.getLogger(name)
        if len(self._logger.handlers) > 0:
            return

        self._logger.setLevel(LOG_LEVEL)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter('[%(name)s] [%(levelname)s] %(message)s'))
        self._logger.addHandler(stream_handler)

    def debug(self, message):
        self._logger.debug(message)

    def info(self, message):
        self._logger.info(message)

    def warning(self, message):
        self._logger.warning(message)

    def error(self, message, exception: Exception=None):
        self._logger.error(message)
        if exception is not None:
            self._logger.exception(exception)