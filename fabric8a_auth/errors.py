"""Errors."""


class AuthError(Exception):
    """Authentication error.

    This error can be caught and handled by Flask's `@app.errorhandler`.

    Example:
        @app.errorhandler(AuthError)
        def api_401_handler(err):
            return flask.jsonify(error=err.error), err.status_code
    """

    def __init__(self, status_code=401, error='authentication error'):
        """Constructor.

        :param status_code:, int, HTTP status code
        :param error: str, error description
        """
        super().__init__(self)
        self.status_code = status_code
        self.error = error

    def __repr__(self):
        return 'AuthError(status_code={s},error={e})'.format(s=self.status_code, e=self.error)

    def __str__(self):
        return 'AuthError({s}): {e}'.format(s=self.status_code, e=self.error)
