__author__ = 'daslanian'

from flask import current_app, request, abort
from functools import update_wrapper

from .exceptions import AuthorizationError, AuthenticationError


def hmac_auth(rights=None):
    def decorator(f):
        def wrapped_function(*args, **kwargs):
            try:
                current_app.hmac_manager.is_authorized(request, rights)
            except (AuthenticationError, AuthorizationError):
                # TODO(daslanian): in the future we may want to find a way to allow the user to define custom handlers
                abort(403)
            else:
                return f(*args, **kwargs)

        return update_wrapper(wrapped_function, f)

    return decorator
