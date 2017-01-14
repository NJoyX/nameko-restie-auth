from restie import codes
from restie.exceptions import HttpError


class Forbidden(HttpError):
    status_code = codes.FORBIDDEN
    error_code = 'FORBIDDEN'
