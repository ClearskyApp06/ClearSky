from quart_schema import validate_querystring, validate_response

from . import blueprint, decorators, schemas


@blueprint.bp.route("/echo")
@decorators.handle_errors
@validate_querystring(schemas.Echo)
@validate_response(schemas.Echo)
async def echo(query_args: schemas.Echo) -> tuple[schemas.Echo, int]:
    return schemas.Echo(msg=query_args.msg)
