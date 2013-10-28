#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "libuv/include/uv.h"
#include "http-parser/http_parser.h"

#define INFO(fmt, params...) fprintf(stderr, "INFO: " fmt "\n", params);
#define ERROR(fmt, params...) fprintf(stderr, "ERROR: "fmt "\n", params);

// Links: 
// https://gist.github.com/Jxck/4305806

typedef struct {
    uv_tcp_t handle;
    http_parser parser;
    uv_buf_t initbuf;
    int headers_complete;
    int upgrade_sent;
    
    int backend_connected;
    uv_tcp_t backend_handle;
} client_t;

static void on_client_connect(uv_stream_t*, int status);
static void on_client_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void on_client_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
static void on_client_close(uv_handle_t* handle);
static void on_client_write(uv_write_t* req, int status);

static int on_client_headers_complete(http_parser* parser);
static int on_client_header_field(http_parser* parser, const char* at, size_t length);
static int on_client_header_value(http_parser* parser, const char* at, size_t length);

static void on_backend_connect(uv_connect_t* req, int status);
static void on_backend_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void on_backend_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);
static void on_backend_close(uv_handle_t* handle);
static void on_backend_write(uv_write_t* req, int status);

#define HTTP_TLS_UPGRADE_HEADERS \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Date: Sun, 15 Sep 2013 20:44:53 GMT\r\n" \
	"Server: CUPS/1.6 IPP/2.1\r\n" \
	"Connection: Keep-Alive\r\n" \
	"Keep-Alive: timeout=30\r\n" \
	"Content-Language: en_US\r\n" \
	"Connection: Upgrade\r\n" \
	"Upgrade: TLS/1.0,HTTP/1.1\r\n" \
	"Content-Length: 0\r\n" \
	"\r\n"

#define MAX_HTTP_HEADER_SIZE (16 * 1024)

// Global variables
static uv_loop_t* loop;
static uv_tcp_t server;
static http_parser_settings parser_settings;

static int listen_port = 7000;

int main() {
    int r;
    struct sockaddr_in addr;

    // Initialize global variables
    loop = uv_default_loop();
    parser_settings.on_headers_complete = on_client_headers_complete;
    parser_settings.on_header_field = on_client_header_field;
    parser_settings.on_header_value = on_client_header_value;

    // Parse bind address
    assert(0 == uv_ip4_addr("0.0.0.0", listen_port, &addr));

    // Initialize tcp handle for listning tcp server
    r = uv_tcp_init(loop, &server);
    if (r) {
        INFO("Socket creation error: %s", uv_err_name(r));
        return 1;
    }

    // Bind to port 7000
    r = uv_tcp_bind(&server, (const struct sockaddr*) &addr);
    if (r) {
        INFO("Bind error: %s", uv_err_name(r));
        return 1;
    }

    // Listen with a backlog of SOMAXXCONN/128 connections
    r = uv_listen((uv_stream_t*)&server, SOMAXCONN, on_client_connect);
    if (r) {
        INFO("Listen error: %s", uv_err_name(r));
        return 1;
    }

	INFO("MAX_HTTP_HEADER_SIZE set to %d", MAX_HTTP_HEADER_SIZE);
    INFO("Listning on %d and waiting for connections", listen_port);
    uv_run(loop, UV_RUN_DEFAULT);
    return 0;
}

static void on_client_connect(uv_stream_t* server, int status) {
    int r;

    // Check for connection errors
    if (status != 0) {
        fprintf(stderr, "Connect error %s\n", uv_err_name(status));
        return;
    }

    // Allocate client
    client_t* client = malloc(sizeof(client_t));
    assert(client != NULL);
	
	// Create initial buffer to store http headers and initialize other fields
    client->initbuf.base = malloc(MAX_HTTP_HEADER_SIZE);
    client->initbuf.len = 0;
	client->headers_complete = 0;
	client->backend_connected = 0;
	client->upgrade_sent = 0;
	
    // Initialize http_parser and save client for later use
    http_parser_init(&client->parser, HTTP_REQUEST);

    INFO("New connection from %s", "");

    // Initialize new handle for the client connection and add to loop
    r = uv_tcp_init(loop, &client->handle);
    assert(r == 0);
 
    // Accept the new connection and set handle on client
    r = uv_accept(server, (uv_stream_t*)&client->handle);
    assert(r == 0);

	// Save client so we can access it in the read and http_parse callback 
    client->handle.data = client;
    client->parser.data = client;
    client->backend_handle.data = client;
    
    // Start reading data from client
    r = uv_read_start((uv_stream_t*)&client->handle, on_client_alloc, on_client_read);
    assert(r == 0);
}

static void on_client_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    int r;
    size_t parsed;
    client_t* client = (client_t*) handle->data;
    uv_write_t* wreq;
    uv_connect_t* creq;
    uv_buf_t wbuf;
    char* wbase;
    struct sockaddr_in backend_addr;

    if (nread >= 0) {
    	if(!client->backend_connected && !client->upgrade_sent) {
    		parsed = http_parser_execute(&client->parser, &parser_settings, buf->base, nread);
    	
    		INFO("Parsed %d bytes of data", (int)parsed);
    		if(parsed < nread) {
	    		ERROR("parse error, %d", (int)parsed);
    		}
    	}
    	
        if(client->backend_connected) {
        	INFO("Send %d bytes of data to backend, with bufsize %d", (int)nread, (int)buf->len);
        	wbuf = uv_buf_init(buf->base, nread);
        	wreq = (uv_write_t*) malloc(sizeof *wreq);
        	wreq->data = wbuf.base;
        	r = uv_write(wreq, (uv_stream_t*)&client->backend_handle, &wbuf, 1, on_backend_write);
        	assert(r == 0);
        	// TODO: Limit the outstanding buffers we can have so a fast client won't use all our memory
        	// if(client->buffer_len > MAX_PER_CONN_BUFFERS) { uv_stop_read(handle); }
        
        } else if(client->upgrade_sent) {
        	//TODO: Move to function
        	INFO("Connect to backend as client has been upgraded", "");

        	// Overwrite initbuf with TLS Hello that was sent after the upgrade
        	INFO("Overwrite initbuf with %d bytes of buf", (int)nread);
        	memcpy(client->initbuf.base, buf->base, nread);
        	client->initbuf.len = nread;
        	
        	assert(0 == uv_ip4_addr("192.168.10.20", 443, &backend_addr));

		    r = uv_tcp_init(loop, &client->backend_handle);
		    assert(r == 0);
		        
		    creq = (uv_connect_t*)malloc(sizeof *creq);
		    creq->data = client;
		    r = uv_tcp_connect(creq, &client->backend_handle, (const struct sockaddr*) &backend_addr, on_backend_connect);
		    assert(r == 0);
        
        } else if(client->headers_complete) {
	    	// Connect to https if it's a connection upgrade
	        if(client->parser.upgrade) {
		        // Send upgrade confirm of upgrade headers 
		    	INFO("Send %d bytes of HTTPS upgrade headers to client", (int)sizeof(HTTP_TLS_UPGRADE_HEADERS) - 1);
		        
		        // Copy HTTP_TLS_UPGRADE_HEADERS to new wbuf
		        wbase = malloc(sizeof(HTTP_TLS_UPGRADE_HEADERS) - 1);
		        wbuf = uv_buf_init(wbase, sizeof(HTTP_TLS_UPGRADE_HEADERS) - 1);
		        memcpy(wbuf.base, HTTP_TLS_UPGRADE_HEADERS, sizeof(HTTP_TLS_UPGRADE_HEADERS) - 1);
		        wreq = (uv_write_t*) malloc(sizeof *wreq);
		        wreq->data = wbuf.base;
		        printf("Send to client: %.*s\n", (int)wbuf.len, wbuf.base);
		        r = uv_write(wreq, (uv_stream_t*)&client->handle, &wbuf, 1, on_client_write);
		        assert(r == 0);
		        
		        client->upgrade_sent = 1;
		        
	    	} else {
	    		//TODO: Move to function
	    		INFO("Connect to backend as we got all the client headers", "");
	        	assert(0 == uv_ip4_addr("127.0.0.1", 80, &backend_addr));
	        	
	        	// Copy buf to initbuf, so we can send it to the backend
	        	memcpy(client->initbuf.base + client->initbuf.len, buf->base, nread);
    			client->initbuf.len += nread;

			    r = uv_tcp_init(loop, &client->backend_handle);
			    assert(r == 0);
			        
			    creq = (uv_connect_t*)malloc(sizeof *creq);
			    creq->data = client;
			    r = uv_tcp_connect(creq, &client->backend_handle, (const struct sockaddr*) &backend_addr, on_backend_connect);
			    assert(r == 0);
	    	}

    	} else if(client->initbuf.len + nread <= MAX_HTTP_HEADER_SIZE) {
    		INFO("Save %d bytes of data for backend", (int)nread);
    		memcpy(client->initbuf.base + client->initbuf.len, buf->base, nread);
    		client->initbuf.len += nread;
    	
    	} else {
    		INFO("Initbuf is larger than allowed size: %d", MAX_HTTP_HEADER_SIZE);
    	}
    	
    } else {
    	INFO("on_client_read %d", (int)nread);
        // Client closed connection
    	if(buf->len) {
    		free(buf->base);
    	}
    	/* TODO: Look into what buffer we need to free on client disconnect
    	if(client->initbuf.len) {
    		free(client->initbuf.base);
    	} */
    	
		INFO("Client %s is closing it's connection", "");
		uv_close((uv_handle_t*)&client->handle, on_client_close);
		if(client->backend_connected) {
			uv_close((uv_handle_t*)&client->backend_handle, on_backend_close);
		}
    }
}

static int on_client_headers_complete(http_parser* parser) {
    int r;
    client_t* client = (client_t*) parser->data;

    INFO("HTTP Headers parsed: %s", "");
    client->headers_complete = 1;
    
    // Stop parsing after getting header
    return 1;
}

static int on_client_header_field(http_parser* parser, const char* at, size_t length) {
    printf("Header field: %.*s\n", (int)length, at);
    return 0;
}

static int on_client_header_value(http_parser* parser, const char* at, size_t length) {
    printf("Header value: %.*s\n", (int)length, at);
    return 0;
}

static void on_client_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_client_close(uv_handle_t* handle) {
    client_t* client = (client_t*) handle->data;
    INFO("Client closed connection", "");
    // Free client and initial buffer
    free(client);
}

static void on_client_write(uv_write_t* req, int status) {
    INFO("After write", "");
    // Free buffer
    free(req->data);
    free(req);
}

static void on_backend_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_backend_connect(uv_connect_t* req, int status) {
    int r;
    uv_write_t* wreq;
    client_t* client = (client_t*) req->data;
    
    // Check for connection errors
    if (status != 0) {
        fprintf(stderr, "Connect error %s\n", uv_err_name(status));
        return;
    }

    INFO("Connected to backend", "");
    client->backend_connected = 1;

	// Send initbuf to backend if its not zero	
	INFO("Send %d bytes of init data to backend", (int)client->initbuf.len);
	printf("Send to backend: %.*s\n", (int)client->initbuf.len, client->initbuf.base);
	wreq = (uv_write_t*) malloc(sizeof *wreq);
	wreq->data = client->initbuf.base;
	uv_write(wreq, (uv_stream_t*)&client->backend_handle, &client->initbuf, 1, on_backend_write);

    // Start reading data from backend
    r = uv_read_start((uv_stream_t*)&client->backend_handle, on_backend_alloc, on_backend_read);
    assert(r == 0);

	// Free connect request
    free(req);
}

static void on_backend_read(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    int r;
    client_t* client = (client_t*) handle->data;
    uv_write_t* wreq;
    uv_buf_t wbuf;

    INFO("Backend read", "");

    if (nread >= 0) {
        //TODO, check if client is still connected
        INFO("Send %d bytes of data to client", (int)nread);
        wbuf = uv_buf_init(buf->base, nread);
        wreq = (uv_write_t*) malloc(sizeof *wreq);
        wreq->data = wbuf.base;
        printf("Send to client: %.*s\n", (int)wbuf.len, wbuf.base);
        r = uv_write(wreq, (uv_stream_t*)&client->handle, &wbuf, 1, on_client_write);
        assert(r == 0);

     } else {
     	INFO("on_backend_read %d", (int)nread);
        // Client closed connection
    	if(buf->len) {
    		free(buf->base);
    	}
    	/* TODO: Look into what buffer we need to free on client disconnect, fx. client->initbuf */
    	INFO("Backend %s is closing it's connection", "");
		uv_close((uv_handle_t*)&client->handle, on_client_close);
		uv_close((uv_handle_t*)&client->backend_handle, on_backend_close);
    }
}

static void on_backend_write(uv_write_t* req, int status) {
    INFO("After backend write", "");
    
    // Check for connection errors
    if (status != 0) {
        fprintf(stderr, "Write error %s\n", uv_err_name(status));
        return;
    }
    
    // Free buffer
    free(req->data);
    free(req);
}

static void on_backend_close(uv_handle_t* handle) {
    client_t* client = (client_t*) handle->data;
    INFO("Backend closed connection", "");
}

