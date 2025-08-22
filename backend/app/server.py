# backend/app/server.py
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from .data_handler import data_handler as DataHandler

OK=200; BAD_REQUEST=400; SERVER_ERROR=500; NOT_FOUND=404; NOT_AUTHENTICATED=401

def main():
    app = Flask(__name__)
    CORS(app)
    dh = DataHandler()

    dh.start_scheduler()

    limiter = Limiter(key_func=get_remote_address)
    limiter.init_app(app)

    @app.errorhandler(BAD_REQUEST)
    def bad_request(error):
        return dh.make_msg(error=str(error)), BAD_REQUEST

    @app.errorhandler(NOT_AUTHENTICATED)
    def unauthorized(error):
        return dh.make_msg(error=str(error)), NOT_AUTHENTICATED

    @app.errorhandler(SERVER_ERROR)
    def server_error(error):
        return dh.make_msg(error=str(error)), SERVER_ERROR

    @app.route('/', methods=['GET'])
    def server_stat():
        msg, status = dh.check_api_key(request)
        if status != OK:
            return dh.make_msg(error=msg), status
        return dh.make_msg(content=dh.get_server_stat()), OK

    @app.route('/get_api_key', methods=['GET'])
    def get_api_key():
        msg, status, content = dh.create_new_user(request)
        if status != OK:
            return dh.make_msg(error=msg), status
        return jsonify(content), OK

    @app.route('/submit_new_phish_urls', methods=['PUT'])
    @limiter.limit("10 per minute")
    def submit_new_phish_urls():
        msg, status = dh.check_api_key(request)
        if status != OK:
            return dh.make_msg(error=msg), status

        msg, status, json_list = dh.validate_json(request)
        if status != OK:
            return dh.make_msg(error=msg), status

        dh.daily_phish_set.update(json_list)
        return dh.make_msg(content={'message': 'URLs accepted', 'count': len(json_list)}), OK

    # final debug damnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn

    # ===== DEBUG: get current daily submissions (what the extension sent today) =====
    @app.route('/debug/daily_submissions', methods=['GET'])
    def debug_daily_submissions():
        msg, status = dh.check_api_key(request)
        if status != OK:
            return dh.make_msg(error=msg), status
        # החזרה מסודרת של הרשימה הנוכחית
        items = sorted(list(dh.daily_phish_set))
        return dh.make_msg(content={"count": len(items), "daily_urls": items}), OK

    # ===== DEBUG: get recent DB rows =====
    @app.route('/debug/db_recent', methods=['GET'])
    def debug_db_recent():
        msg, status = dh.check_api_key(request)
        if status != OK:
            return dh.make_msg(error=msg), status

        try:
            limit = int(request.args.get('limit', 50))
        except Exception:
            limit = 50

        with dh.get_db_session() as session:
            # מחזיר את ה־N האחרונים לפי last_seen (אם None – לפי first_seen)
            from backend.app.models import UBE_phish_DB
            rows = (
                session.query(UBE_phish_DB)
                .order_by(UBE_phish_DB.last_seen.desc().nullslast(), UBE_phish_DB.first_seen.desc())
                .limit(limit)
                .all()
            )
            out = []
            for r in rows:
                out.append({
                    "url": r.url,
                    "first_seen": str(r.first_seen) if r.first_seen else None,
                    "last_seen": str(r.last_seen) if r.last_seen else None,
                    "reports_count": r.reports_count,
                    "on_air": r.on_air,
                    "checked": r.checked,
                })
        return dh.make_msg(content={"count": len(out), "rows": out}), OK

    # ===== DEBUG: trigger daily routine now (instead of waiting 23:00) =====
    @app.route('/debug/run_daily', methods=['POST'])
    def debug_run_daily():
        msg, status = dh.check_api_key(request)
        if status != OK:
            return dh.make_msg(error=msg), status
        dh.run_daily_routine()
        return dh.make_msg(content={"message": "daily_routine triggered"}), OK

    app.run(host="0.0.0.0", port=8000, debug=True)

if __name__ == "__main__":
    main()
