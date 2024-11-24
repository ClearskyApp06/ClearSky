import functools
from collections.abc import Awaitable
from http import HTTPStatus
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from quart import request, session

import database_handler
import errors
from config_helper import logger
from environment import get_api_var
from errors import ClearskyException, InternalServerError
from helpers import get_ip

from . import schemas

if TYPE_CHECKING:
    from collections.abc import Callable

P = ParamSpec("P")
T = TypeVar("T", bound=Awaitable)


def api_key_required(key_type: str) -> "Callable":
    def decorator(func: "Callable[P, T]") -> "Callable[P, T]":
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            api_environment = get_api_var()

            provided_api_key = request.headers.get("X-API-Key")

            api_keys = await database_handler.get_api_keys(api_environment, key_type, provided_api_key)
            try:
                if (
                    provided_api_key not in api_keys.get("key")
                    or api_keys.get("valid") is False
                    or api_keys.get(key_type) is False
                ):
                    ip = await get_ip()
                    logger.warning(f"<< {ip}: given key:{provided_api_key} Unauthorized API access.")
                    session["authenticated"] = False
                    raise errors.Unauthorized("You are not authorized to access this resource.")

            except AttributeError:
                logger.error(f"API key not found for type: {key_type}")
                session["authenticated"] = False

                raise errors.Unauthorized("You are not authorized to access this resource.")
            else:
                logger.info(f"Valid key {provided_api_key} for type: {key_type}")

                session["authenticated"] = True  # Set to True if authenticated

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def handle_errors(fn: "Callable[P, T]") -> "Callable[P, T]":
    @functools.wraps(fn)
    async def inner(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await fn(*args, **kwargs)
        except ClearskyException as exc:
            if exc.status_code // 100 == 5:
                logger.exception("Server error")
            return schemas.ErrorEnvelope(
                error=schemas.ErrorResponse(code=exc, message=exc.msg_for_user)
            ), exc.status_code
        except Exception as exc:
            logger.exception("Unhandled server error")
            return schemas.ErrorEnvelope(
                error=schemas.ErrorResponse(
                    code=InternalServerError(str(exc)), message=InternalServerError.default_message
                )
            ), HTTPStatus.INTERNAL_SERVER_ERROR

    return inner
