from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_serializer

Tmod = TypeVar("Tmod", bound=BaseModel)
Texc = TypeVar("Texc", bound=Exception)


class ResponseMeta(BaseModel):
    next_: HttpUrl | None = Field(alias="next", default=None)
    prev: HttpUrl | None = None
    count: int | None = None


class ErrorResponse(BaseModel, Generic[Texc]):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    code: Texc
    message: str | None

    @field_serializer("code")
    def serialize_exc(self, code: Texc) -> str:
        return type(code).__name__


class ErrorEnvelope(BaseModel, Generic[Texc]):
    error: ErrorResponse[Texc]


class ResponseEnvelope(BaseModel, Generic[Tmod]):
    data: list[Tmod]
    links: ResponseMeta | None = None


class Echo(BaseModel):
    msg: str
