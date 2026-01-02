"""
 HTTP Server
 Author: Eyal Kahanovich
 Purpose: build basic understanding of http servers
"""

import socket
import os
import logging

# Configure logging with different levels for different types of information
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('http_server.log'),  # Log to file
        logging.StreamHandler()  # Also log to console
    ]
)

# Create separate loggers for different components
server_logger = logging.getLogger('Server')
request_logger = logging.getLogger('Request')
file_logger = logging.getLogger('File')
error_logger = logging.getLogger('Error')

# Default URL to serve when root path is requested
DEFAULT_URL = "index.html"

# Dictionary mapping old URLs to their new locations for 302 redirects
REDIRECTION_DICTIONARY = {
    "/old-page": "/index.html",
    "/moved": "/index.html",
    "/redirect": "/index.html"
}

# Character encoding for text-based files and HTTP headers
UTF = "utf-8"

# Maximum number of pending connections in the server queue
QUEUE_SIZE = 10

# Server listening address (0.0.0.0 means all available interfaces)
IP = '0.0.0.0'

# Server listening port
PORT = 8080

# Socket timeout in seconds for client connections
SOCKET_TIMEOUT = 2

# Root directory for web files (using tilde expansion for home directory)
WEBROOT = "~/p/python/http-server/WEB-ROOT"


def get_file_data(file_name):
    """
    Read and return the contents of a file from the webroot directory.
    
    This function handles both text and binary files appropriately:
    - Text files (HTML, CSS, JS): read as text with UTF-8 encoding
    - Binary files (images, icons): read in binary mode
    
    Parameters:
    -----------
    file_name : str
        The name of the file to read (relative to WEBROOT)
    
    Returns:
    --------
    bytes or str or None
        File contents as bytes for binary files, string for text files,
        or None if file doesn't exist or error occurs
    """
    try:
        # Expand the WEBROOT path to handle ~ home directory notation
        webroot = os.path.expanduser(WEBROOT)
        filepath = os.path.join(webroot, file_name)
        
        file_logger.debug(f"Attempting to read file: {filepath}")
        
        # Check if file exists before attempting to read
        if not os.path.isfile(filepath):
            file_logger.warning(f"File not found: {filepath}")
            return None
            
        # Handle binary files (images, icons) - read as bytes
        if file_name.endswith(('.jpg', '.jpeg', '.png', '.gif', '.ico')):
            file_logger.debug(f"Reading binary file: {file_name}")
            with open(filepath, 'rb') as f:
                content = f.read()
                file_logger.debug(f"Successfully read {len(content)} bytes from {file_name}")
                return content
        else:
            # Handle text files (HTML, CSS, JS) - read as text with UTF-8
            file_logger.debug(f"Reading text file: {file_name}")
            with open(filepath, 'r', encoding=UTF) as f:
                content = f.read()
                file_logger.debug(f"Successfully read {len(content)} characters from {file_name}")
                return content
    except PermissionError as e:
        file_logger.error(f"Permission denied reading file {file_name}: {e}")
        return None
    except Exception as e:
        # Log error but don't crash - let calling function handle missing files
        error_logger.error(f"Error reading file {file_name}: {e}", exc_info=True)
        return None


def handle_client_request(resource, client_socket):
    """
    Process an HTTP request and send appropriate response to client.
    
    This function implements the main HTTP request handling logic:
    1. Check for redirections (302 responses)
    2. Validate access permissions (403 responses)
    3. Locate and read requested files
    4. Handle missing files (404 responses)
    5. Send successful responses with correct content types
    6. Handle server errors (500 responses)
    
    Parameters:
    -----------
    resource : str
        The requested resource path (without leading slash)
    client_socket : socket.socket
        Socket object for communication with the client
    
    Returns:
    --------
    None
        Sends response directly to client socket
    """
    client_address = client_socket.getpeername()
    
    try:
        # Set default URL if empty request
        if resource == '':
            uri = DEFAULT_URL
            request_logger.info(f"Empty resource requested, using default: {DEFAULT_URL}")
        else:
            uri = resource.lstrip('/')  # Remove leading slash if present
        
        request_logger.info(f"Processing request from {client_address}: {uri}")
        
        # Check if the requested URI is in the redirection dictionary
        if '/' + uri in REDIRECTION_DICTIONARY:
            new_location = REDIRECTION_DICTIONARY['/' + uri]
            request_logger.info(f"Redirecting {uri} to {new_location} (302)")
            body = f"<html><body><h1>302 Moved Temporarily</h1><p>Resource moved to <a href='{new_location}'>{new_location}</a></p></body></html>"
            http_header = f"HTTP/1.1 302 Found\r\nLocation: {new_location}\r\nContent-Length: {len(body)}\r\n\r\n"
            client_socket.send(http_header.encode() + body.encode())
            return
        
        # List of path patterns that should be forbidden
        forbidden_paths = ['admin', 'private', '.git', '.env', 'config']
        if any(forbidden in uri.lower() for forbidden in forbidden_paths):
            request_logger.warning(f"Access forbidden for {uri} from {client_address}")
            error_body = "<html><body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body></html>"
            http_header = f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {len(error_body)}\r\n\r\n"
            client_socket.send(http_header.encode() + error_body.encode())
            return
        
        # Extract file extension to determine content type
        if '.' in uri:
            file_type = uri.split('.')[-1].lower()
            request_logger.debug(f"File type detected: {file_type}")
        else:
            # Default to HTML for files without extension
            file_type = 'html'
            uri = uri if uri.endswith('.html') else uri + '.html'
            request_logger.debug(f"No extension, defaulting to HTML: {uri}")
        
        # Attempt to read the requested file
        data = get_file_data(uri)
        
        # Handle file not found (404 Not Found)
        if data is None:
            request_logger.warning(f"File not found: {uri}")
            error_body = "<html><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>"
            http_header = f"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {len(error_body)}\r\n\r\n"
            client_socket.send(http_header.encode() + error_body.encode())
            return
        
        # Convert text files to bytes, keep binary files as-is
        if file_type in ['html', 'css', 'js']:
            if isinstance(data, str):
                data_bytes = data.encode(UTF)
                request_logger.debug(f"Converted text file to bytes: {len(data_bytes)} bytes")
            else:
                data_bytes = data
        else:
            # Binary files (images, etc.) are already bytes
            data_bytes = data
        
        # Calculate content length for HTTP header
        content_length = len(data_bytes)
        request_logger.debug(f"Content length: {content_length} bytes")
        
        # Set appropriate content type header
        if file_type == 'html':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type in ['jpg', 'jpeg']:
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type == 'png':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type == 'gif':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: image/gif\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type == 'css':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type == 'js':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {content_length}\r\n\r\n"
        elif file_type == 'ico':
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: image/x-icon\r\nContent-Length: {content_length}\r\n\r\n"
        else:
            # Default to plain text for unknown file types
            http_header = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {content_length}\r\n\r\n"
        
        # Combine header and body, send to client
        http_response = http_header.encode() + data_bytes
        client_socket.send(http_response)
        request_logger.info(f"Successfully served {uri} ({content_length} bytes) to {client_address}")
        
    except socket.error as e:
        error_logger.error(f"Socket error while handling request from {client_address}: {e}")
    except Exception as e:
        # Catch-all for unexpected errors during request processing
        error_logger.error(f"Unexpected error handling request for {uri} from {client_address}: {e}", exc_info=True)
        try:
            error_body = "<html><body><h1>500 Internal Server Error</h1><p>The server encountered an error and could not complete your request.</p></body></html>"
            http_header = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: {len(error_body)}\r\n\r\n"
            client_socket.send(http_header.encode() + error_body.encode())
        except:
            error_logger.error("Failed to send 500 error response to client")


def validate_http_request(request):
    """
    Validate that a request is a properly formatted HTTP GET request.
    
    Performs several checks:
    1. Request is not empty
    2. Proper HTTP request line format (METHOD URI VERSION)
    3. Method is GET
    4. Version starts with HTTP/
    5. Resource path starts with /
    6. No directory traversal attempts (..)
    
    Parameters:
    -----------
    request : str
        The raw HTTP request received from the client
    
    Returns:
    --------
    tuple (bool, str or None)
        First element: True if valid HTTP GET request, False otherwise
        Second element: Requested resource (without leading slash) if valid,
                       None if invalid
    """
    if not request:
        request_logger.debug("Received empty request")
        return False, None

    # Split request by HTTP line terminators
    lines = request.split('\r\n')
    
    if len(lines) == 0 or not lines[0]:
        request_logger.debug("Request has no lines")
        return False, None
    
    # Parse the request line (first line)
    requestline = lines[0].strip()
    requestparts = requestline.split()
    
    request_logger.debug(f"Request line: {requestline}")
    
    # Request line must have exactly 3 parts: METHOD URI VERSION
    if len(requestparts) != 3:
        request_logger.warning(f"Invalid request line format: {requestline}")
        return False, None
    
    method, resource, version = requestparts

    # Only accept GET method
    if method.upper() != 'GET':
        request_logger.warning(f"Unsupported method: {method}")
        return False, None
    
    # Must be an HTTP request
    if not version.upper().startswith('HTTP/'):
        request_logger.warning(f"Invalid HTTP version: {version}")
        return False, None

    # Resource path must start with /
    if not resource.startswith('/'):
        request_logger.warning(f"Resource doesn't start with /: {resource}")
        return False, None
        
    # Prevent directory traversal attacks
    if '..' in resource:
        request_logger.warning(f"Directory traversal attempt detected: {resource}")
        return False, None

    # Root path serves the default document
    if resource == '/':
        request_logger.debug("Request for root, serving default document")
        return True, "index.html"
    
    # Return the resource path without leading slash
    request_logger.debug(f"Valid request for resource: {resource}")
    return True, resource.lstrip('/')


def handle_client(client_socket):
    """
    Main loop for handling a single client connection.
    
    This function:
    1. Reads data from the client socket
    2. Validates it as HTTP
    3. Processes valid requests
    4. Sends error responses for invalid requests
    5. Closes connection when done
    
    Parameters:
    -----------
    client_socket : socket.socket
        Socket object for the connected client
    
    Returns:
    --------
    None
    """
    client_address = client_socket.getpeername()
    server_logger.info(f"Client connected from {client_address}")
    
    try:
        while True:
            # Receive data from client (max 4KB per read)
            request_data = client_socket.recv(4096).decode(UTF)
            if not request_data:
                server_logger.info(f"Client {client_address} disconnected")
                client_socket.close()
                return
            
            request_logger.debug(f"Received {len(request_data)} bytes from {client_address}")
            
            # Validate the HTTP request
            valid_http, resource = validate_http_request(request_data)
            if valid_http:
                request_logger.info(f"Valid HTTP request from {client_address} for {resource}")
                handle_client_request(resource, client_socket)
            else:
                # Send 400 Bad Request for invalid HTTP
                request_logger.warning(f"Invalid HTTP request from {client_address}")
                http_header = "HTTP/1.1 400 BAD REQUEST\r\n\r\n<html><body><h1>400 BAD REQUEST</h1></body></html>"
                client_socket.send(http_header.encode())
                break
                
    except socket.timeout:
        server_logger.warning(f"Socket timeout for client {client_address}")
    except socket.error as e:
        error_logger.error(f"Socket error with client {client_address}: {e}")
    except Exception as e:
        error_logger.error(f"Unexpected error handling client {client_address}: {e}", exc_info=True)
    finally:
        try:
            client_socket.close()
            server_logger.info(f"Connection closed for {client_address}")
        except:
            pass


def main():
    """
    Main server function that sets up the listening socket and accepts connections.
    
    This function:
    1. Initiates a socket
    2. Binds to the specified IP and port
    3. Listens for incoming connections
    4. Accepts connections and spawns client handlers
    5. Handles socket errors
    6. Closes sockets
    
    The server runs indefinitely until interrupted.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Bind to all interfaces on the specified port
        server_socket.bind((IP, PORT))
        server_logger.info(f"Server started on {IP}:{PORT}")
        server_logger.info(f"Web root directory: {os.path.expanduser(WEBROOT)}")
        
        # Start listening with specified queue size
        server_socket.listen(QUEUE_SIZE)
        server_logger.info(f"Listening for connections with queue size {QUEUE_SIZE}")

        # Main server loop
        while True:
            try:
                # Wait for and accept new client connections
                server_logger.debug("Waiting for new connections...")
                client_socket, client_address = server_socket.accept()
                server_logger.info(f"Accepted connection from {client_address}")
                
                # Set timeout to prevent hanging connections
                client_socket.settimeout(SOCKET_TIMEOUT)
                
                # Handle the client connection
                handle_client(client_socket)
                
            except socket.timeout:
                server_logger.debug("Socket accept timeout")
                continue
            except KeyboardInterrupt:
                server_logger.info("Server shutdown requested by user")
                break
            except Exception as e:
                error_logger.error(f"Error accepting connection: {e}", exc_info=True)
                continue
                
    except socket.error as err:
        # Log fatal socket errors (binding/listening failures)
        error_logger.critical(f"Socket error in main server loop: {err}")
    except Exception as e:
        error_logger.critical(f"Unexpected error in main server loop: {e}", exc_info=True)
    finally:
        # Ensure server socket is always closed on exit
        try:
            server_socket.close()
            server_logger.info("Server socket closed")
        except:
            pass
        server_logger.info("Server shutdown complete")


if __name__ == "__main__":
    # Log server startup
    server_logger.info("=" * 50)
    server_logger.info("HTTP Server Starting")
    server_logger.info("=" * 50)

    #asserts for http request validation
    assert validate_http_request("GET / HTTP/1.1\r\n\r\n")[0] is True
    assert validate_http_request("POST / HTTP/1.1\r\n\r\n")[0] is False
 
    # Call the main handler function
    main()
