#!/usr/bin/env python3
"""
Frontend Development Server Launcher
Starts HTTP server with user-friendly messages and browser auto-open
"""

import http.server
import socketserver
import webbrowser
import time
import os
import sys

def start_frontend_server(port=3000, auto_open=True):
    """
    Start the frontend development server with user-friendly output
    """

    # Get the current directory (should be frontend/)
    current_dir = os.getcwd()
    print(f"📁 Serving files from: {current_dir}")

    # Create handler
    Handler = http.server.SimpleHTTPRequestHandler

    try:
        # Start server
        with socketserver.TCPServer(("", port), Handler) as httpd:
            server_url = f"http://localhost:{port}"

            print("\n" + "="*60)
            print("🚀 FRONTEND DEVELOPMENT SERVER STARTED")
            print("="*60)
            print(f"🌐 Server URL: {server_url}")
            print(f"📂 Serving directory: {os.path.basename(current_dir)}")
            print("📝 Files available:")
            print("   • index.html (main page)")
            print("   • css/style.css (styles)")
            print("   • js/ (JavaScript files)")
            print("="*60)
            print("💡 Tips:")
            print("   • Press Ctrl+C to stop the server")
            print("   • Refresh browser to see changes")
            print("   • Edit files and save to see live updates")
            print("="*60)

            # Auto-open browser
            if auto_open:
                print("🌍 Opening browser automatically...")
                time.sleep(1)  # Brief pause for server to start
                webbrowser.open(server_url)
                print("✅ Browser opened! If not, click the link above.")
            else:
                print("🔗 Click the link above to open in browser.")

            print("\n🔄 Server is running... (Ctrl+C to stop)\n")

            # Serve forever
            httpd.serve_forever()

    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user (Ctrl+C)")
        print("👋 Thanks for using the frontend development server!")

    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"❌ Error: Port {port} is already in use!")
            print("💡 Try a different port: python start_frontend.py 3001")
        else:
            print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Allow custom port via command line argument
    port = 3000
    auto_open = True

    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid port number. Using default 3000.")

    if len(sys.argv) > 2 and sys.argv[2].lower() == "no-open":
        auto_open = False

    start_frontend_server(port, auto_open)