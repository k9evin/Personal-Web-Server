/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include "http.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bufio.h"
#include "hexdump.h"
#include "main.h"
#include "socket.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static const char *NEVER_EMBED_A_SECRET_IN_CODE = "supa secret";

static bool handle_html5_fallback(struct http_transaction *ta, char *basedir);
static bool validate_token(struct http_transaction *ta);
bool http_keep_alive(struct http_client *self);

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool http_parse_request(struct http_transaction *ta) {
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)  // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);

    request[len - 2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);

    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);

    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta) {
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))  // empty CRLF
            return true;

        header[len - 2] = '\0';
        /* Each header field consists of a name followed by a
         * colon (":") and the field value. Field names are
         * case-insensitive. The field value MAY be preceded by
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        printf("%s: %s\n", field_name, field_value);

        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Cookie")) {
            char *endptr;
            char *token;

            while ((token = strtok_r(field_value, "; ", &field_value))) {
                strtok_r(token, "=", &endptr);
                if (!strcmp(token, "auth_token")) {
                    char *cookies = strtok_r(NULL, "; ", &endptr);
                    ta->req_cookies = cookies;
                    break;
                }
            }
        }

        // Handle range request
        if (!strcasecmp(field_name, "Range")) {
            char *endptr;
            char *token;

            token = strtok_r(field_value, ": ", &endptr);
            if (token == NULL)
                return false;

            if (strtok_r(token, "=", &endptr) == NULL) {
                return false;
            }

            printf("token: %s\n", token);

            if (!strcmp(token, "bytes")) {
                char *start = strtok_r(NULL, "-", &endptr);
                char *end = strtok_r(NULL, " ", &endptr);

                ta->req_start = atoi(start);
                if (end != NULL)
                    ta->req_end = atoi(end);
                else
                    ta->req_end = -1;

                ta->req_range = true;
            }
            
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void http_add_header(buffer_t *resp, char *key, char *fmt, ...) {
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len) {
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction *ta, buffer_t *res) {
    buffer_appends(res, "HTTP/1.1 ");

    switch (ta->resp_status) {
        case HTTP_OK:
            buffer_appends(res, "200 OK");
            break;
        case HTTP_PARTIAL_CONTENT:
            buffer_appends(res, "206 Partial Content");
            break;
        case HTTP_BAD_REQUEST:
            buffer_appends(res, "400 Bad Request");
            break;
        case HTTP_PERMISSION_DENIED:
            buffer_appends(res, "403 Permission Denied");
            break;
        case HTTP_NOT_FOUND:
            buffer_appends(res, "404 Not Found");
            break;
        case HTTP_METHOD_NOT_ALLOWED:
            buffer_appends(res, "405 Method Not Allowed");
            break;
        case HTTP_REQUEST_TIMEOUT:
            buffer_appends(res, "408 Request Timeout");
            break;
        case HTTP_REQUEST_TOO_LONG:
            buffer_appends(res, "414 Request Too Long");
            break;
        case HTTP_NOT_IMPLEMENTED:
            buffer_appends(res, "501 Not Implemented");
            break;
        case HTTP_SERVICE_UNAVAILABLE:
            buffer_appends(res, "503 Service Unavailable");
            break;
        case HTTP_INTERNAL_ERROR:
        default:
            buffer_appends(res, "500 Internal Server Error");
            break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta) {
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta) {
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction *ta, enum http_response_status status, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta) {
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found",
                      bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world
 * servers use more extensive lists such as /etc/mime.types !
 */
static const char *
guess_mime_type(char *filename) {
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";

    return "text/plain";
}

/* Handle HTTP transaction for static files. ! */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir) {
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);

    if (!req_path || !strcmp(req_path, "/"))
        return handle_html5_fallback(ta, basedir);


    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else if (html5_fallback)
            return handle_html5_fallback(ta, basedir);
        else 
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        if (html5_fallback)
            return handle_html5_fallback(ta, basedir);
        return send_not_found(ta);
    }

    
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    bool success;

    if (!ta->req_range) {
        ta->resp_status = HTTP_OK;
        off_t from = 0, to = st.st_size - 1;

        off_t content_length = to + 1 - from;
        add_content_length(&ta->resp_headers, content_length);
        

        success = send_response_header(ta);
        if (!success)
            goto out;

        // sendfile may send fewer bytes than requested, hence the loop
        while (success && from <= to)
            success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

    } else {
        ta->resp_status = HTTP_PARTIAL_CONTENT;
        off_t from, to;

        if (ta->req_end == -1)
            from = ta->req_start, to = st.st_size - 1;
        else
            from = ta->req_start, to = ta->req_end;


        http_add_header(&ta->resp_headers, "Content-Range", "bytes %lld-%lld/%lld",
                        (long long)from, (long long)to, (long long)st.st_size);

        off_t content_length = to + 1 - from;
        add_content_length(&ta->resp_headers, content_length);

        success = send_response_header(ta);
        if (!success)
            goto out;

        // sendfile may send fewer bytes than requested, hence the loop
        while (success && from <= to)
            success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;
    }
out:
    close(filefd);
    return success;
    // return false; //!
}

static void
jwt_perror(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static bool
handle_video(struct http_transaction *ta, char *basedir) {
    // Use the opendir and readdir calls to list all mp4 files in the server’s root directory
    DIR *dir;
    struct dirent *entry;
    char fname[PATH_MAX];
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);

    if (strcmp(req_path, "/api/video") == 0) {
        dir = opendir(basedir);

        json_t *array = json_array();
        if (dir == NULL) {
            return send_error(ta, HTTP_INTERNAL_ERROR, "Could not open directory.");
        }
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, ".mp4") != NULL) {
                json_t *obj = json_object();

                // get the size of the file, and print it
                snprintf(fname, sizeof fname, "%s/%s", basedir, entry->d_name);

                struct stat st;
                int rc = stat(fname, &st);
                if (rc == -1) {
                    return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
                }
                json_object_set(obj, "size", json_integer(st.st_size));
                json_object_set(obj, "name", json_string(entry->d_name));
                json_array_append(array, obj);
            }
        }
        char *json_str = json_dumps(array, JSON_INDENT(2));

        ta->resp_status = HTTP_OK;
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        buffer_appends(&ta->resp_body, json_str);

        return send_response(ta);
    } else {
        ta->resp_status = HTTP_METHOD_NOT_ALLOWED;
        send_response(ta);
    }

    return false;
}

static bool
handle_api(struct http_transaction *ta) {
    // Handle HTTP_GET requests

    if (ta->req_method == HTTP_GET) {
        ta->resp_status = HTTP_OK;

        if (!validate_token(ta)) {
            buffer_appends(&ta->resp_body, "{}");
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        } else {
            jwt_t *mytoken;
            if (jwt_decode(&mytoken, ta->req_cookies,
                           (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                           strlen(NEVER_EMBED_A_SECRET_IN_CODE))) {
                jwt_perror("jwt_decode");
            }

            char *grants = jwt_get_grants_json(mytoken, NULL);
            if (grants == NULL)
                jwt_perror("jwt_get_grants_json");

            buffer_appends(&ta->resp_body, grants);
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        }
        return send_response(ta);
    } else if (ta->req_method == HTTP_POST) {
        json_error_t error;
        jwt_t *token;
        char *req_body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
        json_t *json_files = json_loadb(req_body, ta->req_content_len, 0, &error);
        const char *username = json_string_value(json_object_get(json_files, "username"));
        const char *password = json_string_value(json_object_get(json_files, "password"));

        // If the username and password does not match, return 403 Forbidden
        if (username == NULL || password == NULL ||
            strcmp(username, "user0") || strcmp(password, "thepassword")) {
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        }

        if (jwt_new(&token))
            jwt_perror("jwt_new");

        // sub describes which the server will recognize the bearer of the claim
        if (jwt_add_grant(token, "sub", "user0"))
            jwt_perror("jwt_add_grant sub");

        time_t now = time(NULL);
        // iat is the time at which the claim was issued, inc seconds since Jan 1, 1970
        if (jwt_add_grant_int(token, "iat", now))
            jwt_perror("jwt_add_grant iat");

        // exp is the time at which the claim will expire
        if (jwt_add_grant_int(token, "exp", now + token_expiration_time))
            jwt_perror("jwt_add_grant exp");

        //  The signature is obtained in the form of a JSON Web Token
        if (jwt_set_alg(token, JWT_ALG_HS256,
                        (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                        strlen(NEVER_EMBED_A_SECRET_IN_CODE)))
            jwt_perror("jwt_set_alg");

        char *encoded = jwt_encode_str(token);
        if (encoded == NULL)
            jwt_perror("jwt_encode_str");

        ta->resp_status = HTTP_OK;

        char *grants = jwt_get_grants_json(token, NULL);
        if (grants == NULL)
            jwt_perror("jwt_get_grants_json");

        // Follow the format of the Set-Cookie header, and choose a name for the cookie
        http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/", encoded);
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        buffer_appends(&ta->resp_body, grants);

        return send_response(ta);
    } else {
        ta->resp_status = HTTP_METHOD_NOT_ALLOWED;
        send_response(ta);
    }

    return false;
}

/* Set up an http client, associating it with a bufio buffer. */
void http_setup_client(struct http_client *self, struct bufio *bufio) {
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool http_handle_transaction(struct http_client *self) {
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);

    if (strstr(req_path, "../") != NULL || strstr(req_path, "/..") != NULL) {
        return send_error(&ta, HTTP_NOT_FOUND, "NOT FOUND");
    }

    if (STARTS_WITH(req_path, "/api")) {
        if (strcmp(req_path, "/api/login") == 0)
            rc = handle_api(&ta);
        else if (strcmp(req_path, "/api/video") == 0)
            rc = handle_video(&ta, server_root);
        else
            return send_error(&ta, HTTP_NOT_FOUND, "NOT FOUND");
    } else if (STARTS_WITH(req_path, "/private")) {
        if (ta.req_method == HTTP_POST || ta.req_method == HTTP_UNKNOWN)
            return send_error(&ta, HTTP_METHOD_NOT_ALLOWED, "Method not allowed.");

        if (!validate_token(&ta)) {
            return send_error(&ta, HTTP_PERMISSION_DENIED, "Permission denied.");  // !
        } else {
            rc = handle_static_asset(&ta, server_root);
        }
    } else {
        rc = handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc && !(ta.req_version == HTTP_1_0);
}

static bool handle_html5_fallback(struct http_transaction *ta, char *basedir) {
    char fname[PATH_MAX];

    snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1)
        return send_not_found(ta);

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from = 0, to = st.st_size - 1;

    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}

static bool validate_token(struct http_transaction *ta) {
    jwt_t *mytoken;

    if (ta->req_cookies == NULL) 
        return false;

    if (jwt_decode(&mytoken, ta->req_cookies,
                   (unsigned char *)NEVER_EMBED_A_SECRET_IN_CODE,
                   strlen(NEVER_EMBED_A_SECRET_IN_CODE)) != 0) {
        return false;
    }

    char *grants = jwt_get_grants_json(mytoken, NULL);
    if (grants == NULL)
        jwt_perror("jwt_get_grants_json");

    time_t now = time(NULL);
    int exp = jwt_get_grant_int(mytoken, "exp");
    if (exp < now) {
        return false;
    }

    // int iat = jwt_get_grant_int(mytoken, "iat");
    // if (iat > now) {
    //     return false;
    // }

    const char *sub = jwt_get_grant(mytoken, "sub");
    if (strcmp(sub, "user0") != 0) {
        return false;
    }

    return true;
}

bool http_keep_alive(struct http_client *self) {
    while (http_handle_transaction(self)) {
    }
    return true;
}