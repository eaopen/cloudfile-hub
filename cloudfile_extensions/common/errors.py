"""Safe domain errors that never serialize internal exceptions or credentials."""

from dataclasses import dataclass


@dataclass
class ContractError(Exception):
    code: str
    message: str
    status: int = 400

    def __post_init__(self):
        Exception.__init__(self, self.message)

    def response(self, request_id):
        return {"code": self.code, "message": self.message, "request_id": request_id}


def invalid(message="Invalid request"):
    return ContractError("INVALID_REQUEST", message)
