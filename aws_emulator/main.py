import os
from flask import Flask, request, Response

from core import XML, RequestHelper


def create_app():
    app = Flask(__name__)
    mode = os.environ.get("SERVICE_MODE", "all").lower()
    if mode not in ("all", "ec2", "s3"):
        raise RuntimeError(f"Invalid SERVICE_MODE={mode!r}; expected one of: all, ec2, s3")

    enable_ec2 = mode in ("all", "ec2")
    enable_s3 = mode in ("all", "s3")

    if enable_ec2:
        import db
        import iam_db
        import ec2_routes
        import iam_routes

        if db.is_configured():
            iam_db.init_schema()
        else:
            app.logger.warning(
                "DATABASE_URL not set: IAM user/access-key management is disabled "
                "(EC2/VPC and the fixed 'emulator'/'test' identity still work)."
            )

        @app.route("/", methods=["POST"])
        def query_endpoint():
            req = RequestHelper(request.form)
            action = req.get("Action")
            if not action:
                return Response(XML.wrap("Error", "<Code>InvalidAction</Code>"), status=400, mimetype="text/xml")
            print(f"--> {action}")

            resp = ec2_routes.dispatch(action, req)
            if resp is not None:
                return resp

            resp = iam_routes.dispatch(action, req, request=request)
            if resp is not None:
                return resp

            print(f"!!! 400 Bad Request: Action '{action}' not matched !!!")
            return Response(XML.wrap("Error", "<Code>InvalidAction</Code>"), status=400, mimetype="text/xml")

    if enable_s3:
        try:
            import s3_routes
        except ImportError:
            app.logger.warning(
                "SERVICE_MODE requests S3 but the s3_routes module isn't present in "
                "this build; S3 endpoints are disabled."
            )
        else:
            s3_routes.register(app)

    return app


# Module-level `app` so `flask run` / gunicorn's default `main:app` also work
# without needing the separate wsgi.py entrypoint.
app = create_app()


def main():
    port = int(os.environ.get("PORT", "4566"))
    app.run(debug=True, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
