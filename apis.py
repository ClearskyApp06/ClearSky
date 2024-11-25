# apis.py

from collections.abc import Awaitable
from datetime import timedelta
from functools import wraps
from http import HTTPStatus
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from quart import Blueprint, jsonify, render_template, send_file, send_from_directory, session
from quart_rate_limiter import RateLimitExceeded, rate_limit

from core import (
    api_key_required,
    autocomplete,
    block_stats,
    check_api_keys,
    convert_uri_to_url,
    cursor_recall_status,
    fun_facts,
    funer_facts,
    get_blocked_search,
    get_blocking_search,
    get_blocklist,
    get_did_info,
    get_handle_history_info,
    get_handle_info,
    get_in_common_blocked,
    get_in_common_blocklist,
    get_internal_status,
    get_list_info,
    get_moderation_lists,
    get_single_blocklist,
    get_total_users,
    logger,
    request,
    retrieve_csv_data,
    retrieve_csv_files_info,
    retrieve_dids_per_pds,
    retrieve_subscribe_blocks_blocklist,
    retrieve_subscribe_blocks_single_blocklist,
    store_data,
    time_behind,
    verify_handle,
)
from errors import (
    BadRequest,
    ClearskyException,
    DatabaseConnectionError,
    ExceedsFileSizeLimit,
    FileNameExists,
    NoFileProvided,
    NotFound,
    NotImplement,
)
from helpers import generate_session_number, get_ip

if TYPE_CHECKING:
    from collections.abc import Callable

    from quart import Response

P = ParamSpec("P")
T = TypeVar("T", bound=Awaitable)
api_blueprint = Blueprint("api", __name__)


def handle_errors(fn: "Callable[P, T]") -> "Callable[P, T]":
    @wraps(fn)
    async def inner(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return await fn(*args, **kwargs)
        except ClearskyException as exc:
            if exc.status_code // 100 == 5:
                logger.exception("Server error")
            response = jsonify({"error": {"data": str(exc)}})
            response.status_code = exc.status_code
            return response
        except RateLimitExceeded as exc:
            response = jsonify({"error": {"data": "Rate limit exceeded"}})
            response.headers["Retry-After"] = exc.retry_after
            response.status_code = HTTPStatus.TOO_MANY_REQUESTS
            return response
        except Exception:
            logger.exception("Unhandled server error")
            response = jsonify({"error": {"data": "Internal server error"}})
            response.status_code = 500
            return response

    return inner


# ======================================================================================================================
# ================================================== Static Pages ======================================================
@api_blueprint.route("/", methods=["GET"])
async def index():
    # Generate a new session number and store it in the session
    if "session_number" not in session:
        session["session_number"] = generate_session_number()

    return await render_template("index.html")


@api_blueprint.route("/fediverse", methods=["GET"])
async def fediverse():
    # Generate a new session number and store it in the session
    if "session_number" not in session:
        session["session_number"] = generate_session_number()

    return await render_template("data-transfer.html")


@api_blueprint.route("/fedi-delete-request", methods=["GET"])
async def fedi_delete_request():
    # Generate a new session number and store it in the session
    if "session_number" not in session:
        session["session_number"] = generate_session_number()

    return await render_template("fedi-delete-request.html")


@api_blueprint.route("/images/favicon.png", methods=["GET"])
async def favicon1():
    return await send_from_directory("images", "favicon.png")


@api_blueprint.route("/images/apple-touch-icon.png", methods=["GET"])
async def favicon2():
    return await send_from_directory("images", "apple-touch-icon.png")


@api_blueprint.route("/images/apple-touch-icon-120x120.png", methods=["GET"])
async def favicon3():
    return await send_from_directory("images", "apple-touch-icon-120x120.png")


@api_blueprint.route("/images/apple-touch-icon-152x152.png", methods=["GET"])
async def favicon4():
    return await send_from_directory("images", "apple-touch-icon-152x152.png")


@api_blueprint.route("/images/CleardayLarge.png", methods=["GET"])
async def logo():
    return await send_from_directory("images", "CleardayLarge.png")


@api_blueprint.route("/frequently_asked", methods=["GET"])
async def faq():
    session_ip = await get_ip()

    logger.info(f"{session_ip} - FAQ requested.")

    return await render_template("coming_soon.html")


@api_blueprint.route("/coming_soon", methods=["GET"])
async def coming_soon():
    session_ip = await get_ip()

    logger.info(f"{session_ip} - Coming soon requested.")

    return await render_template("coming_soon.html")


@api_blueprint.route("/status", methods=["GET"])
async def always_200():
    return "OK", 200


@api_blueprint.route("/contact", methods=["GET"])
async def contact():
    session_ip = await get_ip()

    logger.info(f"{session_ip} - Contact requested.")

    return await render_template("contact.html")


@api_blueprint.route("/api/v1/anon/images/logo", methods=["GET"])
@rate_limit(5, timedelta(seconds=1))
async def anon_get_logo():
    return await send_from_directory("images", "Clearskylogo.png")


@api_blueprint.route("/api/v1/anon/images/icon", methods=["GET"])
@rate_limit(5, timedelta(seconds=1))
async def anon_get_icon():
    return await send_from_directory("images", "favicon32.png")


@api_blueprint.route("/api/v1/auth/images/logo", methods=["GET"])
@rate_limit(5, timedelta(seconds=1))
async def auth_get_logo():
    return await send_from_directory("images", "Clearskylogo.png")


@api_blueprint.route("/api/v1/auth/images/icon", methods=["GET"])
@rate_limit(5, timedelta(seconds=1))
async def auth_get_icon():
    return await send_from_directory("images", "favicon32.png")


# ======================================================================================================================
# ===================================================== APIs ===========================================================

# ======================================================================================================================
# ===================================================== V1 =============================================================


# ======================================================================================================================
# ============================================= Authenticated API Endpoints ============================================
@api_blueprint.route("/api/v1/auth/blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/auth/blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_blocklist(client_identifier, page) -> "Response":
    return jsonify({"data": await get_blocklist(client_identifier, page)})


@api_blueprint.route("/api/v1/auth/single-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/auth/single-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_single_blocklist(client_identifier, page) -> "Response":
    identifier, status, blocklist_data = await get_single_blocklist(client_identifier, page)
    return jsonify({"identifier": identifier, "status": status, "data": blocklist_data})


@api_blueprint.route("/api/v1/auth/in-common-blocklist/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_in_common_blocklist(client_identifier) -> "Response":
    identifier, common_list = await get_in_common_blocklist(client_identifier)
    return jsonify({"identity": identifier, "data": common_list})


@api_blueprint.route("/api/v1/auth/in-common-blocked-by/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_in_common_blocked_by(client_identifier) -> "Response":
    identifier, common_list = await get_in_common_blocked(client_identifier)
    return jsonify({"identity": identifier, "data": common_list})


@api_blueprint.route("/api/v1/auth/at-uri/<path:uri>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_convert_uri_to_url(uri) -> "Response":
    return {"data": await convert_uri_to_url(uri)}


@api_blueprint.route("/api/v1/auth/total-users", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_total_users() -> "Response":
    raise NotImplement()
    return jsonify({"data": await get_total_users()})


@api_blueprint.route("/api/v1/auth/get-did/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_did_info(client_identifier) -> "Response":
    return jsonify({"data": await get_did_info(client_identifier)})


@api_blueprint.route("/api/v1/auth/get-handle/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_handle_info(client_identifier) -> "Response":
    return jsonify({"data": await get_handle_info(client_identifier)})


@api_blueprint.route("/api/v1/auth/get-handle-history/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_handle_history_info(client_identifier) -> "Response":
    return jsonify({"data": await get_handle_history_info(client_identifier)})


@api_blueprint.route("/api/v1/auth/get-list/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_list_info(client_identifier) -> "Response":
    identifier, list_data = await get_list_info(client_identifier)
    return jsonify({"identifier": identifier, "data": list_data})


@api_blueprint.route("/api/v1/auth/get-moderation-list/<string:input_name>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/auth/get-moderation-list/<string:input_name>/<int:page>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_moderation_lists(input_name, page) -> "Response":
    name, sub_data = await get_moderation_lists(input_name, page)
    return jsonify({"input": name, "data": sub_data})


@api_blueprint.route("/api/v1/auth/blocklist-search-blocked/<client_identifier>/<search_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_blocked_search(client_identifier, search_identifier) -> "Response":
    return jsonify({"data": await get_blocked_search(client_identifier, search_identifier)})


@api_blueprint.route("/api/v1/auth/blocklist-search-blocking/<client_identifier>/<search_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_blocking_search(client_identifier, search_identifier) -> "Response":
    return jsonify({"data": await get_blocking_search(client_identifier, search_identifier)})


@api_blueprint.route("/api/v1/auth/lists/fun-facts", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_fun_facts() -> "Response":
    return await fun_facts()


@api_blueprint.route("/api/v1/auth/lists/funer-facts", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_funer_facts() -> "Response":
    return await funer_facts()


@api_blueprint.route("/api/v1/auth/lists/block-stats", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_block_stats() -> "Response":
    return await block_stats()


@api_blueprint.route("/api/v1/auth/base/autocomplete/<client_identifier>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_autocomplete(client_identifier) -> "Response":
    return await autocomplete(client_identifier)


@api_blueprint.route("/api/v1/auth/base/internal/status/process-status", methods=["GET"])
@handle_errors
@api_key_required("INTERNALSERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_get_internal_status() -> "Response":
    return await get_internal_status()


@api_blueprint.route("/api/v1/auth/base/internal/api-check", methods=["GET"])
@handle_errors
@api_key_required("INTERNALSERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_check_api_keys() -> "Response":
    return await check_api_keys()


@api_blueprint.route("/api/v1/auth/lists/dids-per-pds", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_dids_per_pds() -> "Response":
    return await retrieve_dids_per_pds()


@api_blueprint.route(
    "/api/v1/auth/subscribe-blocks-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"]
)
@api_blueprint.route("/api/v1/auth/subscribe-blocks-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_subscribe_blocks_blocklist(client_identifier, page) -> "Response":
    return await retrieve_subscribe_blocks_blocklist(client_identifier, page)


@api_blueprint.route(
    "/api/v1/auth/subscribe-blocks-single-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"]
)
@api_blueprint.route("/api/v1/auth/subscribe-blocks-single-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@api_key_required("SERVER")
@rate_limit(30, timedelta(seconds=1))
async def auth_subscribe_blocks_single_blocklist(client_identifier, page) -> "Response":
    return await retrieve_subscribe_blocks_single_blocklist(client_identifier, page)


@api_blueprint.route("/api/v1/auth/validation/validate-handle/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(30, timedelta(seconds=1))
async def auth_validate_handle(client_identifier) -> "Response":
    return await verify_handle(client_identifier)


@api_blueprint.route("/api/v1/auth/data-transaction/receive", methods=["POST"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def auth_receive_data() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list file upload request: {session_ip} - {api_key}")

    raise NotImplement()
    try:
        file_name = await request.form
        file_name = file_name.get("filename")

        # Retrieve additional fields
        author = await request.form
        author = author.get("author")

        description = await request.form
        description = description.get("description")

        appeal = await request.form
        appeal = appeal.get("appealsProcess")

        list_type = await request.form
        list_type = list_type.get("listType")

        if file_name is None:
            file_name = request.args.get("filename")
        if author is None:
            author = request.args.get("author")
        if description is None:
            description = request.args.get("description")
        if appeal is None:
            appeal = request.args.get("appealsProcess")
        if list_type is None:
            list_type = request.args.get("listType")

        if not list_type.lower().strip() == "user" or "domain":
            raise BadRequest

        if len(author) > 100 or len(description) > 300 or len(appeal) > 500:
            logger.warning(
                f"Data too long: Author: {len(author)}, Description: {len(description)}, Appeal: {len(appeal)}"
            )
            raise BadRequest

        # Check if the request contains a file
        if not file_name:
            raise BadRequest

        # Check if files were sent in the request
        files = await request.files
        if "file" not in files:
            raise BadRequest("No file provided.")

        # Get the file from the request
        file_storage = files["file"]

        if file_name != file_storage.filename:
            raise BadRequest()

        try:
            # Read the content of the file
            file_content = file_storage.read()
        except Exception as e:
            logger.error(f"Error reading file content, probably not a csv: {file_name} {e}")
            raise BadRequest()

        await store_data(file_content, file_name, author, description, appeal, list_type)

        return jsonify({"message": "File received and processed successfully"}), 200
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except NoFileProvided:
        return jsonify({"error": "No file provided"}), 400
    except FileNameExists:
        return jsonify({"error": "File name already exists"}), 409
    except ExceedsFileSizeLimit:
        return jsonify({"error": "File size limit exceeded."}), 413
    except Exception as e:
        logger.error(f"Error in receive_data: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/auth/data-transaction/retrieve", methods=["GET"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def auth_retrieve_data() -> "Response":
    raise NotImplement()
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list file request: {session_ip} - {api_key}")

    return jsonify({"error": "Not Implemented"}), 501

    try:
        retrieve_lists = request.args.get("retrieveLists")
        file_name = request.args.get("file")  # need to validate the file name
    except AttributeError:
        return jsonify({"error": "Invalid request"}), 400

    try:
        if retrieve_lists == "true" and file_name is not None:
            # Assuming retrieve_csv_data() returns the file path of the CSV file
            file_content = await retrieve_csv_data(file_name)

            if file_content is None:
                return jsonify({"error": "Not found"}), 404

            logger.info(f"Sending file: {file_name}")

            return await send_file(file_content, mimetype="text/csv", as_attachment=True, attachment_filename=file_name)
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        logger.error(f"Error in auth_retrieve_data: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/auth/data-transaction/query", methods=["GET"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def auth_query_data() -> "Response":
    raise NotImplement()
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list query request: {session_ip} - {api_key}")

    return jsonify({"error": "Not Implemented"}), 501

    try:
        get_list = request.args.get("list")
    except AttributeError:
        return jsonify({"error": "Invalid request"}), 400

    try:
        return await retrieve_csv_files_info(get_list)
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        logger.error(f"Error in retrieve_csv_files_info: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/auth/status/time-behind", methods=["GET"])
@handle_errors
@rate_limit(30, timedelta(seconds=2))
async def auth_time_behind() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"time behind request: {session_ip} - {api_key}")

    return await time_behind()


# ======================================================================================================================
# ========================================== Unauthenticated API Endpoints =============================================
@api_blueprint.route("/api/v1/anon/blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/anon/blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_blocklist(client_identifier, page) -> "Response":
    return jsonify({"data": await get_blocklist(client_identifier, page)})


@api_blueprint.route("/api/v1/anon/single-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/anon/single-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_single_blocklist(client_identifier, page) -> "Response":
    identifier, status, blocklist_data = await get_single_blocklist(client_identifier, page)
    return jsonify({"identifier": identifier, "status": status, "data": blocklist_data})


@api_blueprint.route("/api/v1/anon/in-common-blocklist/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_in_common_blocklist(client_identifier) -> "Response":
    identifier, common_list = await get_in_common_blocklist(client_identifier)
    return jsonify({"identity": identifier, "data": common_list})


@api_blueprint.route("/api/v1/anon/in-common-blocked-by/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_in_common_blocked_by(client_identifier) -> "Response":
    identifier, common_list = await get_in_common_blocked(client_identifier)
    return jsonify({"identity": identifier, "data": common_list})


@api_blueprint.route("/api/v1/anon/at-uri/<path:uri>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_convert_uri_to_url(uri) -> "Response":
    return {"data": await convert_uri_to_url(uri)}


@api_blueprint.route("/api/v1/anon/total-users", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_total_users() -> "Response":
    raise NotImplement()
    try:
        return await get_total_users()
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        logger.error(f"Error in anon_get_total_users: {e}")
        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/anon/get-did/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_did_info(client_identifier) -> "Response":
    return jsonify({"data": await get_did_info(client_identifier)})


@api_blueprint.route("/api/v1/anon/get-handle/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_handle_info(client_identifier) -> "Response":
    return jsonify({"data": await get_handle_info(client_identifier)})


@api_blueprint.route("/api/v1/anon/get-handle-history/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_handle_history_info(client_identifier) -> "Response":
    return jsonify({"data": await get_handle_history_info(client_identifier)})


@api_blueprint.route("/api/v1/anon/get-list/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_list_info(client_identifier) -> "Response":
    identifier, list_data = await get_list_info(client_identifier)
    return jsonify({"identifier": identifier, "data": list_data})


@api_blueprint.route("/api/v1/anon/get-moderation-list/<string:input_name>", defaults={"page": 1}, methods=["GET"])
@api_blueprint.route("/api/v1/anon/get-moderation-list/<string:input_name>/<int:page>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_moderation_lists(input_name, page) -> "Response":
    name, sub_data = await get_moderation_lists(input_name, page)
    return jsonify({"input": name, "data": sub_data})


@api_blueprint.route("/api/v1/anon/blocklist-search-blocked/<client_identifier>/<search_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_blocked_search(client_identifier, search_identifier) -> "Response":
    return jsonify({"data": await get_blocked_search(client_identifier, search_identifier)})


@api_blueprint.route("/api/v1/anon/blocklist-search-blocking/<client_identifier>/<search_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_blocking_search(client_identifier, search_identifier) -> "Response":
    return jsonify({"data": await get_blocking_search(client_identifier, search_identifier)})


@api_blueprint.route("/api/v1/anon/lists/fun-facts", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_fun_facts() -> "Response":
    return await fun_facts()


@api_blueprint.route("/api/v1/anon/lists/funer-facts", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_funer_facts() -> "Response":
    return await funer_facts()


@api_blueprint.route("/api/v1/anon/lists/block-stats", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_block_stats() -> "Response":
    return await block_stats()


@api_blueprint.route("/api/v1/anon/base/autocomplete/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_autocomplete(client_identifier) -> "Response":
    return await autocomplete(client_identifier)


@api_blueprint.route("/api/v1/anon/base/internal/status/process-status", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_get_internal_status() -> "Response":
    return await get_internal_status()


@api_blueprint.route("/api/v1/anon/lists/dids-per-pds", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_dids_per_pds() -> "Response":
    return await retrieve_dids_per_pds()


@api_blueprint.route(
    "/api/v1/anon/subscribe-blocks-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"]
)
@api_blueprint.route("/api/v1/anon/subscribe-blocks-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_subscribe_blocks_blocklist(client_identifier: str, page: int) -> "Response":
    return await retrieve_subscribe_blocks_blocklist(client_identifier, page)


@api_blueprint.route(
    "/api/v1/anon/subscribe-blocks-single-blocklist/<client_identifier>", defaults={"page": 1}, methods=["GET"]
)
@api_blueprint.route("/api/v1/anon/subscribe-blocks-single-blocklist/<client_identifier>/<int:page>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_subscribe_blocks_single_blocklist(client_identifier, page) -> "Response":
    return await retrieve_subscribe_blocks_single_blocklist(client_identifier, page)


@api_blueprint.route("/api/v1/anon/validation/validate-handle/<client_identifier>", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=1))
async def anon_validate_handle(client_identifier) -> "Response":
    return await verify_handle(client_identifier)


@api_blueprint.route("/api/v1/anon/data-transaction/receive", methods=["POST"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def anon_receive_data() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list file upload request: {session_ip} - {api_key}")
    raise NotImplement()

    try:
        file_name = await request.form
        file_name = file_name.get("filename")

        # Retrieve additional fields
        author = await request.form
        author = author.get("author")

        description = await request.form
        description = description.get("description")

        appeal = await request.form
        appeal = appeal.get("appealsProcess")

        list_type = await request.form
        list_type = list_type.get("listType")

        if file_name is None:
            file_name = request.args.get("filename")
        if author is None:
            author = request.args.get("author")
        if description is None:
            description = request.args.get("description")
        if appeal is None:
            appeal = request.args.get("appealsProcess")
        if list_type is None:
            list_type = request.args.get("listType")

        if list_type.lower().strip() not in ["user", "domain"]:
            raise BadRequest

        if len(author) > 100 or len(description) > 300 or len(appeal) > 500:
            logger.warning(
                f"Data too long: Author: {len(author)}, Description: {len(description)}, Appeal: {len(appeal)}"
            )
            raise BadRequest

        # Check if the request contains a file
        if not file_name:
            raise BadRequest

        # Check if files were sent in the request
        files = await request.files
        if "file" not in files:
            raise BadRequest("No file provided.")

        # Get the file from the request
        file_storage = files["file"]

        if file_name != file_storage.filename:
            raise BadRequest()

        try:
            # Read the content of the file
            file_content = file_storage.read()
        except Exception as e:
            logger.error(f"Error reading file content, probably not a csv: {file_name} {e}")
            raise BadRequest()

        await store_data(file_content, file_name, author, description, appeal, list_type)

        return jsonify({"message": "File received and processed successfully"}), 200
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except NoFileProvided:
        return jsonify({"error": "No file provided"}), 400
    except FileNameExists:
        return jsonify({"error": "File name already exists"}), 409
    except ExceedsFileSizeLimit:
        return jsonify({"error": "File size limit exceeded."}), 413
    except Exception as e:
        logger.error(f"Error in receive_data: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/anon/data-transaction/retrieve", methods=["GET"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def anon_retrieve_data() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list file request: {session_ip} - {api_key}")

    raise NotImplement()

    try:
        retrieve_lists = request.args.get("retrieveLists")
        file_name = request.args.get("file")  # need to validate the file name
    except AttributeError:
        return jsonify({"error": "Invalid request"}), 400

    try:
        if retrieve_lists == "true" and file_name is not None:
            # Assuming retrieve_csv_data() returns the file path of the CSV file
            file_content = await retrieve_csv_data(file_name)

            if file_content is None:
                return jsonify({"error": "Not found"}), 404

            logger.info(f"Sending file: {file_name}")

            return await send_file(file_content, mimetype="text/csv", as_attachment=True, attachment_filename=file_name)
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        logger.error(f"Error in auth_retrieve_data: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/anon/data-transaction/query", methods=["GET"])
@handle_errors
@rate_limit(1, timedelta(seconds=2))
async def anon_query_data() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"data list query request: {session_ip} - {api_key}")

    raise NotImplement()
    try:
        get_list = request.args.get("list")
    except AttributeError:
        return jsonify({"error": "Invalid request"}), 400

    try:
        return await retrieve_csv_files_info(get_list)
    except DatabaseConnectionError:
        logger.error("Database connection error")
        return jsonify({"error": "Connection error"}), 503
    except BadRequest:
        return jsonify({"error": "Invalid request"}), 400
    except NotFound:
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        logger.error(f"Error in retrieve_csv_files_info: {e}")

        return jsonify({"error": "Internal error"}), 500


@api_blueprint.route("/api/v1/anon/cursor-recall/status", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=2))
async def anon_cursor_recall() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"cursor recall request: {session_ip} - {api_key}")

    return await cursor_recall_status()


@api_blueprint.route("/api/v1/anon/status/time-behind", methods=["GET"])
@handle_errors
@rate_limit(5, timedelta(seconds=2))
async def anon_time_behind() -> "Response":
    session_ip = await get_ip()
    api_key = request.headers.get("X-API-Key")

    logger.info(f"time behind request: {session_ip} - {api_key}")

    return await time_behind()
