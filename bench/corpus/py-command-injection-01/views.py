import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import archive
import runner

WORKSPACE = "/srv/workspace"


def export_project(params):
    project = params.get("project", [""])[0]
    fmt = params.get("format", ["gz"])[0]
    if not project:
        return 400, {"error": "project is required"}
    command = archive.build_archive_command(project, fmt)
    try:
        runner.run(command, cwd=WORKSPACE)
    except runner.CommandFailed as exc:
        return 500, {"error": "export failed", "code": exc.returncode}
    return 200, {"archive": archive.archive_name(project, fmt)}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/export":
            self.send_error(404)
            return
        status, payload = export_project(parse_qs(parsed.query))
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8102), Handler).serve_forever()
