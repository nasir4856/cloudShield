from flask import Flask, jsonify


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_server_error(_error):
        app.logger.exception("Unhandled server error.")
        return jsonify({"error": "Internal server error"}), 500

