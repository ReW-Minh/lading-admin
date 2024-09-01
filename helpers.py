from flask import jsonify

def response(message, code=200, data=None, success=True):
    return jsonify({"data": data, "code": code, "success": success, "message": message})


def success(message, data=None):
    return response(message, 200, data, True)


def error(message, code, data=None):
    return response(message, code, data, False)
