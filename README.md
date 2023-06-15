# Paka Server Documentation

This documentation provides an overview and explanation of a Rust server implemented using Actix Web framework. The server is responsible for generating tokens, managing files, and serving static content.

## Table of Contents

- [Server Structure](#server-structure)
- [API Endpoints](#api-endpoints)
- [Token Generation](#token-generation)
- [File Management](#file-management)
- [Static Content Serving](#static-content-serving)
- [Authentication](#authentication)
- [Configuration](#configuration)

## Server Structure

The Paka server is built using Actix Web, which is a lightweight and powerful web framework. It follows a modular structure and consists of the following main components:

- **Main Function**: The entry point of the server, which initializes the Actix Web application and starts the server.
- **Routes**: Defined using the `actix-web` macros, these routes map to different HTTP endpoints and handle incoming requests.
- **Token Generation**: Handles the generation and encryption of tokens used for authentication and file access.
- **File Management**: Manages the uploading, downloading, and deletion of files on the server.
- **Static Content Serving**: Handles the serving of static files such as HTML, CSS, JavaScript, and images.
- **Authentication**: Verifies the validity of tokens for accessing protected endpoints.
- **Configuration**: Handles the configuration settings of the server, including admin password and file paths.

## API Endpoints

The server exposes the following API endpoints:

- `POST /make-tokens/{count}`: Generates a specified number of tokens for authentication purposes.
- `POST /admin/change-password`: Changes the admin password.
- `GET /file-info/{filename}`: Retrieves information about a file.
- `POST /file/{filename}`: Uploads a file to the server.
- `GET /file/{filename}`: Downloads a file from the server.
- `DELETE /file/{filename}`: Deletes a file from the server.
- `GET /static/{filename}`: Serves static files such as HTML, CSS, JavaScript, and images.
- `GET /`: Serves the main index.html file.

## Token Generation

The server provides a token generation functionality that allows the creation of tokens for authentication and file access. Tokens are generated using a POST request to the `/make-tokens/{count}` endpoint. The provided admin password is validated, and if correct, the specified number of tokens is generated and saved as files on the server. Tokens are valid for one hour only, and they are use once. 

## File Management

The server enables file management functionalities, including file upload, download, and deletion. Files are uploaded using a POST request to the `/file/{filename}` endpoint, where the file is encrypted and saved on the server. Files can be downloaded using a GET request to the same endpoint, and deleted using a DELETE request.

## Static Content Serving

The server serves static files stored in the `./static` directory. When a GET request is made to the `/static/{filename}` endpoint, the corresponding file is served. If the file can be compressed (based on its MIME type), it is compressed and served with the appropriate Content-Encoding header.

## Authentication

To access protected endpoints, clients must include a valid token in the query parameters of the request. The token is validated by checking its existence and expiration time. If the token is valid, the client is granted access to the protected endpoint. Tokens are removed from the server after being used or if they expire.

## Configuration

The server allows configuration through the following settings:

- `ADMIN_PWD_FILE_PATH`: Path to the file storing the admin password.
- `TOKENS_DIR`: Directory where generated tokens are stored.
- `GZIPABLE_TYPES`: Array of MIME types that can be compressed when serving static files.

The server initializes

 with an admin password, which can be changed using the `/admin/change-password` endpoint. The admin password is stored in the `ADMIN_PWD_FILE_PATH` file.

This documentation provides an overview of the Rust server's structure and functionality. For more detailed information, refer to the comments in the code itself.


### Authentication Token Function

The authentication token function is responsible for verifying the validity of a given token. Here's an overview of what happens in this function:

1. The function receives a token as input.
2. It first checks if the token exists and is not empty. If the token is missing or empty, the authentication fails.
3. Next, the function decrypts the token to retrieve the payload, which contains information such as the token's creation time and expiration time.
4. The function checks if the token has expired by comparing the current Unix time (in seconds) with the expiration time stored in the payload.
5. If the token has expired, the authentication fails.
6. If the token is valid and has not expired, the authentication succeeds, and the function returns a boolean value indicating the result.

### Token Making Route

The token-making route is responsible for generating tokens based on the specified count. Here's an overview of what happens in this route:

1. The route receives a POST request to the `/make-tokens/{count}` endpoint, where `{count}` is the desired number of tokens to generate.
2. The provided admin password is extracted from the request.
3. The admin password is compared against the stored admin password (usually read from the `ADMIN_PWD_FILE_PATH` file) to verify its correctness.
4. If the admin password is incorrect, the route returns an appropriate error response.
5. If the admin password is correct, the route generates the specified number of tokens.
6. Each token consists of a payload containing the creation time and expiration time. The creation time is set to the current Unix time (in seconds), and the expiration time is calculated by adding 3600 seconds (1 hour) to the creation time.
7. The tokens are then encrypted and saved as files on the server, typically in the `TOKENS_DIR` directory.
8. The route returns a success response indicating the number of tokens generated.

The inclusion of the expiry check and the calculation involving Unix time is important for ensuring the security and validity of the generated tokens. By setting an expiration time, the tokens become valid only for a specific duration, reducing the risk of unauthorized access if a token is compromised.
