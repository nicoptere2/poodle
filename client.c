/*****************************************************************************
 *                 /!\ YOU SHOULD NOT MODIFY THIS FILE! /!\                  *
 *****************************************************************************/

#include "common.h"


/* Global variables.
 *****************************************************************************/

static char        cookie[17];
static SSL_CTX    *ctx         = NULL;
static SSL        *ssl         = NULL;
static int         srv_fd      = -1;
static int         in_shutdown = 0;


/* Set up client.
 *****************************************************************************/

void cli_setup()
{
  // Pick random secret cookie if not already initialized.
  srand(time(NULL));
  for (unsigned i = 0, j; i < 16; ++i) {
    j = rand() % 62;
    cookie[i] = j < 26 ? 'a'+j : j < 52 ? 'A'+j-26 : '0'+j-52;
  }
  cookie[16] = '\0';

  INFO(0, "Secret cookie is `%s'.", cookie);

  // Initialize OpenSSL library and context.
  SSL_load_error_strings();
  SSL_library_init();

  ctx = SSL_CTX_new(SSLv23_client_method());
  ASSERT_SSL(ctx != NULL,
             "Error creating SSL/TLS client context.");

  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_options(ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
  ASSERT_SSL(SSL_CTX_set_cipher_list(ctx, "DEFAULT") == 1,
             "Error setting cipher list.");

  INFO(0, "Initialized SSL/TLS client context.\n");
}


/* Establish SSL/TLS connection to server.
 *****************************************************************************/

int cli_connect(unsigned port)
{
  // Server parameters.
  static const char addr[] = "127.0.0.1";

  // Initialize client-side socket and connect to server.
  srv_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_LIBC(srv_fd >= 0, "socket",
              "Error creating client socket.");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(port);
  sa.sin_addr.s_addr = inet_addr(addr);

  ASSERT_LIBC(!connect(srv_fd, (struct sockaddr *)&sa, sizeof(sa)), "connect",
              "Error connecting to %s:%u.", addr, port);

  INFO(1, "Connected to %s:%u.", addr, port);

  // Initialize SSL/TLS connection.
  ssl = SSL_new(ctx);
  ASSERT_SSL(ssl != NULL,
             "Error creating SSL connection.");

  ASSERT_SSL(SSL_set_fd(ssl, srv_fd) == 1,
             "Error connecting SSL session to socket.");

  if (SSL_connect(ssl) != 1) {
    FAIL_SSL(0, "Error performing SSL/TLS handshake with server.");
    return -1;
  }

  unsigned cipher = SSL_get_current_cipher(ssl)->id & 0xffff;
  INFO(1, "Initialized %s connection using %s.",
       SSL_get_version(ssl), ssl_trace_str(cipher, ssl_ciphers_tbl));

  return 0;
}


/* Main client loop: send HTTP POST requests to server and receive replies.
 *****************************************************************************/

void cli_loop()
{
  static char buf[1024], req[512];

  fd_set      fd_set;
  int         in_fd  = fileno(stdin);
  int         fd_max = MAX(srv_fd, in_fd);
  int         rc, len, blen, rlen;
  const char *p;

  // Loop until connection is terminated.
  while (1) {

    // Wait on data from standard input or server socket.
    FD_ZERO(&fd_set);
    FD_SET(srv_fd, &fd_set);
    FD_SET( in_fd, &fd_set);
    rc = select(fd_max+1, &fd_set, NULL, NULL, NULL);
    ASSERT_LIBC(rc > 0, "select",
                "Error waiting on standard input or socket for data.");

    // Data is available from server.
    if (FD_ISSET(srv_fd, &fd_set)) {
      // Read data from server.
      len = SSL_read(ssl, buf, sizeof(buf));
      if (len <= 0) {
        if (!len)
          ALERT(1, "Connection was terminated by server.");
        else
          FAIL_SSL(1, "Error reading/decrypting data from server.");
        return;
      }

      INFO(1, "Decrypted %d bytes.", len);
      if (verbose >= 2)
        dump_data(buf, len);
    }

    // Data is available from standard input.
    else if (FD_ISSET(in_fd, &fd_set)) {
      blen = 0;
      do {
        // Read request URI and body from standard input.
        if (!blen) {
          if (fgets(req, sizeof(req), stdin) == NULL)
            return;
          len = strlen(req);
          if (req[len-1] == '\n')
            req[--len] = '\0';

          // Skip when URI and body are too long.
          if (len == sizeof(req)-1) {
            FAIL(0, "Error: Request URI and body cannot exceed %zu bytes.",
                 sizeof(req)-1);
            do {
              if (fgets(req, sizeof(req), stdin) == NULL)
                return;
              len = strlen(req);
            } while (req[len-1] != '\n' && len == sizeof(req)-1);
            continue;
          }

          // URI stops at first space character. Request body then follows.
          char *body = strchr(req, ' ');
          if (body == NULL)
            body = req+len;
          else
            *(body++) = '\0';

          if (*body == '!')
            blen = strtoul(body+1, NULL, 10);
          else
            blen = strlen(body)+2;

          // Format request.
          len = snprintf(buf, sizeof(buf),
                         "POST /%s HTTP/1.1\r\n"
                         "Host: www.secure.com\r\n"
                         "Cookie: secret=%s\r\n"
                         "Content-Length: %d\r\n"
                         "\r\n",
                         req, cookie, blen);
          if (*body != '!') {
            len += snprintf(buf+len, sizeof(buf)-len, "%s\r\n", body);
            blen = 0;
          }
          ASSERT((unsigned)len < sizeof(buf),
                 "Error: HTTP request cannot exceed %zu bytes.", sizeof(buf)-1);
        }

        // Read (part of) request body from standard input.
        else {
          len = fread(buf, 1, MIN((unsigned)blen, sizeof(buf)), stdin);
          if (!len)
            return;
          blen -= len;
        }

        // Send request to server.
        for (p = buf, rlen = len; rlen; p += rc, rlen -= rc) {
          rc = SSL_write(ssl, p, rlen);
          if (rc <= 0) {
            if (!rc)
              ALERT(1, "Connection was terminated by server.");
            else
              FAIL_SSL(1, "Error sending data to server.");
            return;
          }
        }

        INFO(1, "Encrypted %d bytes.", len);
        if (verbose >= 2)
          dump_data(buf, len);
      } while (blen);
    }
  }
}


/* Close SSL/TLS connection to server.
 *****************************************************************************/

void cli_close()
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

  // Close server-side socket.
  if (srv_fd >= 0) {
    ASSERT_LIBC(!close(srv_fd), "close",
                "Error closing server socket.");
    srv_fd = -1;
  }

  INFO(1, "Connection closed.\n");
}


/* Shut down client and clean up.
 *****************************************************************************/

void cli_shutdown()
{
  if (in_shutdown)
    return;
  in_shutdown = 1;

  // Close SSL/TLS connection to server, if any.
  if (ssl != NULL || srv_fd >= 0)
    cli_close();

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
    ALERT(0, "Lost connection to server. Exiting...");
  else
    FAIL(0, "Aborting...");

  cli_shutdown();

  exit(sig == SIGABRT ? EXIT_FAILURE : EXIT_SUCCESS);
}


/* Program entry point.
 *****************************************************************************/

static const char usage[] = "Usage: client [options] <port>\n"
                            "\n"
                            "  <port>  Server port number\n"
                            "\n"
                            "Options:\n"
                            "  -q      Decrease verbosity level\n"
                            "  -v      Increase verbosity level\n";

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
    else
      ASSERT(0, "Invalid command-line option `%s'.\n%s", *argv, usage);
  }

  // Parse mandatory command-line parameters.
  ASSERT(argc <= 1, "Too many parameters.\n%s",        usage);
  ASSERT(argc >= 1, "Missing server port number.\n%s", usage);

  unsigned port = atoi(argv[0]);

  // Set up client.
  cli_setup();

  // Keep trying to connect to server as long as standard input is not closed.
  while (!feof(stdin)) {
    if (!cli_connect(port))
      cli_loop();
    cli_close();
  }

  // Shut down client and clean up.
  cli_shutdown();

  return EXIT_SUCCESS;
}
