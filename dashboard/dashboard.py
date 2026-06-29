from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('index.html', 'rb') as f:
                self.wfile.write(f.read())
        elif self.path == '/api/events':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            events = []
            wal_path = '/tmp/alphvdr/qihse_events.wal'
            if os.path.exists(wal_path):
                with open(wal_path, 'r') as f:
                    for line in f.readlines():
                        events.append(line.strip())
            # Return last 100 events reversed (newest first)
            self.wfile.write(json.dumps(events[-100:][::-1]).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    # Listen on all LAN interfaces
    server = HTTPServer(('0.0.0.0', 8080), DashboardHandler)
    print("[*] ALPHVDR LAN Dashboard running on http://0.0.0.0:8080")
    server.serve_forever()
