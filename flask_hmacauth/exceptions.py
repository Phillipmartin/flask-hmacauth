
class FlaskAwsHmacAuthException(Exception):
    pass


class AuthenticationError(FlaskAwsHmacAuthException):
    pass


class AuthorizationError(FlaskAwsHmacAuthException):
    pass
