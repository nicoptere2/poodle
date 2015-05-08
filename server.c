/*****************************************************************************
 *                 /!\ YOU SHOULD NOT MODIFY THIS FILE! /!\                  *
 *****************************************************************************/

#include "common.h"


/* Global variables.
 *****************************************************************************/

static SSL_CTX    *ctx         = NULL;
static SSL        *ssl         = NULL;
static int         srv_fd      = -1;
static int         cli_fd      = -1;
static int         proto       = 0;
static int         slow_mac    = 0;
static int         in_shutdown = 0;


/* Set up server.
 *****************************************************************************/

// Custom TLS 1.0 server methods (see below).
const SSL_METHOD *my_TLSv1_server_method();

void srv_setup(unsigned port)
{
  // Server parameters.
  static const char cert[] = "cert.pem";
  static const char key[]  = "key.pem";
  static const char addr[] = "127.0.0.1";

  // Disable AES-NI support to avoid using aesni_* functions which perform
  // a first HMAC verification _while_ decrypting data.
  OPENSSL_ia32cap &= ~(UINT64_C(1) << 57);

  // Initialize OpenSSL library and context.
  SSL_load_error_strings();
  SSL_library_init();

  // N.B. Must use custom TLS 1.0 method to circumvent OpenSSL
  // countermeasures.
  ctx = SSL_CTX_new(!proto ?    SSLv3_server_method()
                           : my_TLSv1_server_method());
  ASSERT_SSL(ctx != NULL,
             "Error creating SSL/TLS server context.");

  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
  ASSERT_SSL(SSL_CTX_set_cipher_list(ctx, "AES128-SHA") == 1,
             "Error setting cipher list.");

  INFO(0, "Initialized SSL/TLS server context.");

  // Load certificate and private key.
  ASSERT_SSL(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 1,
             "Error loading certificate file `%s'.", cert);

  ASSERT_SSL(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1,
             "Error loading private key file `%s'.", key);

  ASSERT_SSL(SSL_CTX_check_private_key(ctx) == 1,
             "Mismatch between private key and certificate.");

  INFO(0, "Loaded certificate and private key.");

  // Initialize server socket.
  srv_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_LIBC(srv_fd >= 0, "socket",
              "Error creating server socket.");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(port);
  sa.sin_addr.s_addr = inet_addr(addr);

  ASSERT_LIBC(!bind(srv_fd, (struct sockaddr *)&sa, sizeof(sa)), "bind",
              "Error binding server socket to %s:%u.", addr, port);

  ASSERT_LIBC(!listen(srv_fd, 0), "listen",
              "Error listening on server socket.");

  INFO(0, "Server is ready. Waiting for incoming connections...\n");
}


/* Accept incoming SSL/TLS connection from client.
 *****************************************************************************/

int srv_accept()
{
  // Accept incoming connection.
  struct sockaddr_in sa;
  socklen_t len = sizeof(sa);
  cli_fd = accept(srv_fd, (struct sockaddr *)&sa, &len);
  ASSERT_LIBC(cli_fd >= 0, "accept",
              "Error accepting incoming connection.");

  INFO(1, "Received incoming connection from %s:%u.",
       inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

  // Initialize SSL/TLS connection.
  ssl = SSL_new(ctx);
  ASSERT_SSL(ssl != NULL,
             "Error creating SSL/TLS connection.");

  ASSERT_SSL(SSL_set_fd(ssl, cli_fd) == 1,
             "Error connecting SSL/TLS session to socket.");

  if (SSL_accept(ssl) != 1) {
    FAIL_SSL(1, "Error performing SSL/TLS handshake with client.");
    return -1;
  }

  unsigned cipher = SSL_get_current_cipher(ssl)->id & 0xffff;
  INFO(1, "Initialized %s connection using %s.",
       SSL_get_version(ssl), ssl_trace_str(cipher, ssl_ciphers_tbl));

  return 0;
}


/* Main server loop: receive HTTP POST requests from client and send replies.
 *****************************************************************************/

void srv_loop()
{
  static char buf[1025];
  int         rc, len, blen, rlen;
  const char *p;

  // Loop until connection is terminated.
  while (1) {

    blen = 0;
    do {
      // Receive data from client.
      len = SSL_read(ssl, buf, sizeof(buf)-1);
      if (len <= 0) {
        if (!len)
          ALERT(1, "Connection was terminated by client.");
        else
          FAIL_SSL(1, "Error reading/decrypting data from client.");
        return;
      }
      buf[len] = '\0';

      INFO(1, "Decrypted %d bytes.", len);
      if (verbose >= 2)
        dump_data(buf, len);

      // We are expecting a new HTTP POST request.
      if (!blen) {
        // Make sure this is a valid request.
        p = strstr(buf, "\r\n");
        if (strncmp(buf, "POST /", 6) || p == NULL || p-buf < 9 ||
            strncmp(p-9, " HTTP/1.1", 9)) {
          FAIL(0, "Not a valid HTTP POST request: Missing request line.");
          return;
        }
        p = strstr(p, "\r\nContent-Length: ");
        if (p == NULL || p[18] < '0' || p[18] > '9') {
          FAIL(0, "Not a valid HTTP POST request: Missing Content-Length.");
          return;
        }
        blen = strtoul(p+18, NULL, 10);
        p = strstr(p, "\r\n\r\n");
        if (p == NULL) {
          FAIL(0, "Not a valid HTTP POST request: Missing empty line.");
          return;
        }
        blen -= len - (p+4-buf);
      }

      // We are expecting (part of) a POST request body.
      else
        blen -= len;

      ASSERT(blen >= 0, "Error: Received too much POST data.");
    } while (blen);

    // Format reply.
    len = snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n");
    ASSERT((unsigned)len < sizeof(buf),
           "Error: HTTP reply cannot exceed %zu bytes.", sizeof(buf)-1);

    // Send reply to client.
    p = buf;
    for (p = buf, rlen = len; rlen; p += rc, rlen -= rc) {
      rc = SSL_write(ssl, p, rlen);
      if (rc <= 0) {
        if (!rc)
          ALERT(1, "Connection was terminated by client.");
        else
          FAIL_SSL(1, "Error sending data to client.");
        return;
      }
    }

    INFO(1, "Encrypted %d bytes.", len);
    if (verbose >= 2)
      dump_data(buf, len);
  }
}


/* Close SSL/TLS connection to client.
 *****************************************************************************/

void srv_close()
{
  // Shut down SSL/TLS connection.
  if (ssl != NULL) {
    int rc;
    while (!(rc = SSL_shutdown(ssl)));
    if (rc != 1)
      FAIL_SSL(1, "Error shutting down connection.");
    SSL_free(ssl);
    ssl = NULL;
  }

  // Close client-side socket.
  if (cli_fd >= 0) {
    fd_set         fd_set;
    struct timeval timeout = { .tv_sec = 1 };
    FD_ZERO(&fd_set);
    FD_SET(cli_fd, &fd_set);
    int rc = select(cli_fd+1, &fd_set, NULL, &fd_set, &timeout);
    ASSERT_LIBC(rc >= 0, "select",
                "Error waiting on client socket.");
    if (!rc)
      FAIL(0, "Timeout waiting for client to terminate connection.");

    ASSERT_LIBC(!close(cli_fd), "close",
                "Error closing client socket.");
    cli_fd = -1;
  }

  INFO(1, "Connection closed.\n");
}


/* Shut down server and clean up.
 *****************************************************************************/

void srv_shutdown()
{
  if (in_shutdown)
    return;
  in_shutdown = 1;

  // Close SSL/TLS connection to client, if any.
  if (ssl != NULL || cli_fd >= 0)
    srv_close();

  // Close server socket.
  if (srv_fd >= 0) {
    ASSERT_LIBC(!close(srv_fd), "close",
                "Error closing server socket.");
    srv_fd = -1;
  }

  // Clean up OpenSSL context.
  if (ctx != NULL) {
    SSL_CTX_free(ctx);
    ctx = NULL;
  }

  ERR_free_strings();
}


/* Signal handler.
 *****************************************************************************/

void sig_handler(int sig)
{
  if (sig == SIGINT || sig == SIGTERM)
    ALERT(0, "Interruption detected. Exiting...");
  else if (sig == SIGPIPE)
    ALERT(0, "Lost connection to client. Exiting...");
  else
    FAIL(0, "Aborting...");

  srv_shutdown();

  exit(sig == SIGABRT ? EXIT_FAILURE : EXIT_SUCCESS);
}


/* Program entry point.
 *****************************************************************************/

static const char usage[] = "Usage: server [options] <port>\n"
                            "\n"
                            "  <port>  Server port number\n"
                            "\n"
                            "Options:\n"
                            "  -ssl3      Use SSL 3.0 protocol\n"
                            "  -tls1      Use TLS 1.0 protocol\n"
                            "  -slow-mac  Use slow MAC algorithm in TLS 1.0\n"
                            "  -q         Decrease verbosity level\n"
                            "  -v         Increase verbosity level\n";

int main(int argc, char **argv)
{
  // Install signal handler.
  {
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sa.sa_flags   = 0;
    sigemptyset(&sa.sa_mask);
    ASSERT_LIBC(!sigaction(SIGINT,  &sa, NULL) &&
                !sigaction(SIGTERM, &sa, NULL) &&
                !sigaction(SIGABRT, &sa, NULL) &&
                !sigaction(SIGPIPE, &sa, NULL), "sigaction",
                "Error installing signal handler");
  }

  // Parse command-line options.
  for (--argc, ++argv; argc && **argv == '-'; --argc, ++argv) {
    char *p = *argv+1;
    if (*p == 'v' || *p == 'q') {
      for (; *p == 'v' || *p == 'q'; ++p)
        verbose += *p == 'v' ? 1 : -1;
      verbose = MAX(verbose, 0);
      ASSERT(*p == '\0', "Invalid command-line option `%s'.\n%s",
             *argv, usage);
    }
    else if (!strcmp(p, "ssl3"))
      proto = 0;
    else if (!strcmp(p, "tls1"))
      proto = 1;
    else if (!strcmp(p, "slow-mac"))
      slow_mac = 1;
    else
      ASSERT(0, "Invalid command-line option `%s'.\n%s", *argv, usage);
  }

  // Parse mandatory command-line parameters.
  ASSERT(argc <= 1, "Too many parameters.\n%s",        usage);
  ASSERT(argc >= 1, "Missing server port number.\n%s", usage);

  unsigned port = atoi(argv[0]);

  // Set up server.
  srv_setup(port);

  // Process incoming connections from clients.
  while (1) {
    if (!srv_accept())
      srv_loop();
    srv_close();
  }

  // Shut down server and clean up.
  srv_shutdown();

  return EXIT_SUCCESS;
}


/* Patch OpenSSL's tls1_enc method to circumvent countermeasures.
 * /!\ Warning: Very ugly & fragile!
 *****************************************************************************/

// Copied verbatim from OpenSSL's ssl/ssl_locl.h.
// -------8<--------8<--------8<--------8<--------8<--------8<--------8<-------
/*
 * This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff It is a bit
 * of a mess of functions, but hell, think of it as an opaque structure :-)
 */
typedef struct ssl3_enc_method {
    int (*enc) (SSL *, int);
    int (*mac) (SSL *, unsigned char *, int);
    int (*setup_key_block) (SSL *);
    int (*generate_master_secret) (SSL *, unsigned char *, unsigned char *,
                                   int);
    int (*change_cipher_state) (SSL *, int);
    int (*final_finish_mac) (SSL *, const char *, int, unsigned char *);
    int finish_mac_length;
    int (*cert_verify_mac) (SSL *, int, unsigned char *);
    const char *client_finished_label;
    int client_finished_label_len;
    const char *server_finished_label;
    int server_finished_label_len;
    int (*alert_value) (int);
    int (*export_keying_material) (SSL *, unsigned char *, size_t,
                                   const char *, size_t,
                                   const unsigned char *, size_t,
                                   int use_context);
    /* Various flags indicating protocol version requirements */
    unsigned int enc_flags;
    /* Handshake header length */
    unsigned int hhlen;
    /* Set the handshake header */
    void (*set_handshake_header) (SSL *s, int type, unsigned long len);
    /* Write out handshake message */
    int (*do_write) (SSL *s);
} SSL3_ENC_METHOD;
// ------->8-------->8-------->8-------->8-------->8-------->8-------->8-------

// Original tls1_enc method.
int (*old_tls1_enc)(SSL *, int);

// Drop-in replacement for tls1_enc.
int my_tls1_enc(SSL *s, int send)
{
  // Call original method.
  int ret = old_tls1_enc(s, send);

  if (!send) {
    // Early abort when bad padding found.
    if (ret == -1)
      return 0;

    // Simulate slow MAC computation.
    if (slow_mac) {
      EVP_MD_CTX *hash = s->read_hash;
      if (hash != NULL && hash->digest != NULL) {
        int mac_size   = EVP_MD_CTX_size(hash);
        int block_size = EVP_MD_CTX_block_size(hash);
        int len        = s->s3->rrec.length - mac_size;
        usleep(((len+13+block_size-1) / block_size + 3) * 10);
      }
    }
  }

  return ret;
}

// Custom TLS 1.0 server methods.
const SSL_METHOD *my_TLSv1_server_method()
{
  static SSL_METHOD      method;
  static SSL3_ENC_METHOD ssl3_enc;

  // Get current methods.
  method   = *TLSv1_server_method();
  ssl3_enc = *method.ssl3_enc;

  // Replace tls1_enc.
  old_tls1_enc = ssl3_enc.enc;
  ssl3_enc.enc = &my_tls1_enc;

  // Return new methods.
  method.ssl3_enc = &ssl3_enc;
  return &method;
}
