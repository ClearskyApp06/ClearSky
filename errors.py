# errors.py

import sys
from http import HTTPStatus
from typing import ClassVar

if sys.version_info < (3, 13):
    too_large_status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
else:
    too_large_status = HTTPStatus.CONTENT_TOO_LARGE


class ClearskyException(Exception):
    status_code: ClassVar[HTTPStatus] = HTTPStatus.BAD_REQUEST
    default_message: ClassVar[str] = "Internal error"

    def __init__(self, msg: str = "", msg_for_user: str | None = None):
        self.args = (msg or self.default_message,)
        self.msg_for_user = msg_for_user or self.default_message


class BadRequest(ClearskyException):
    status_code = HTTPStatus.BAD_REQUEST
    default_message = "Invalid request"


class Unauthorized(ClearskyException):
    status_code = HTTPStatus.UNAUTHORIZED
    default_message = "Unauthorized"


class NotFound(ClearskyException):
    status_code = HTTPStatus.BAD_REQUEST
    default_message = "Not found"


class DatabaseConnectionError(ClearskyException):
    status_code = HTTPStatus.SERVICE_UNAVAILABLE
    default_message = "Connection error"


class NoFileProvided(ClearskyException):
    status_code = HTTPStatus.BAD_REQUEST
    default_message = "No file provided"


class FileNameExists(ClearskyException):
    status_code = HTTPStatus.CONFLICT
    default_message = "File name already exists"


class ExceedsFileSizeLimit(ClearskyException):
    status_code = too_large_status
    default_message = "File size limit exceeded"


class InternalServerError(ClearskyException):  # 500
    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    default_message = "Internal error"


class NotImplement(ClearskyException):  # 501
    status_code = HTTPStatus.NOT_IMPLEMENTED
    default_message = "Not implemented"
