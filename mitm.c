#include "common.h"


/* Callback functions for attacking the SSL/TLS connection as a
 * (wo)man-in-the-middle.
 * You'll only need to write code here!
 *
 * The arguments to both `on_client_record' and `on_server_record' are:
 *
 *   type: SSL/TLS record type:
 *           SSL3_RT_CHANGE_CIPHER_SPEC (0x14)
 *           SSL3_RT_ALERT              (0x15)
 *           SSL3_RT_HANDSHAKE          (0x16)
 *           SSL3_RT_APPLICATION_DATA   (0x17)
 *           TLS1_RT_HEARTBEAT          (0x18)
 *
 *   ver:  protocol version:
 *           SSL3_VERSION (0x0300)
 *           TLS1_VERSION (0x0301)
 *
 *   len:  pointer to length (in bytes) of record data; can be modified if
 *         needed (set to negative value to drop the record without forwarding
 *         it).
 *
 *   data: pointer to buffer of SSL3_RT_MAX_PLAIN_TEXT bytes, containing
 *         record data; can be modified if needed.
 *****************************************************************************/

// Keep track of handshake progress:
//   0: initial state                      (handshake incomplete)
//   1: received client's ChangeCipherSpec (handshake incomplete)
//   2: received server's ChangeCipherSpec (handshake incomplete)
//   3: received server's Finished         (handshake complete)
//-----------------------------------------------------------------------------
static int handshake;

// Called each time a fresh TCP connection is made from client to server.
//-----------------------------------------------------------------------------
void on_new_connection()
{
  handshake = 0;
}

// Called each time the client sends an SSL/TLS record to the server.
//-----------------------------------------------------------------------------
void on_client_record(int type, int ver, int *len, char *data)
{
  // Use ChangeCipherSpec to keep track of handshake progress.
  if (type == SSL3_RT_CHANGE_CIPHER_SPEC) {
    ASSERT(handshake == 0,
           "Error: Unexpected ChangeCipherSpec from client.");
    ++handshake;
  }

  // If record is application data...
  else if (type == SSL3_RT_APPLICATION_DATA && handshake == 3) {
    if (verbose >= 2)
      dump_data(data, *len);
    // ...
  }

  // If record is error...
  else if (type == SSL3_RT_ALERT && handshake == 3) {
    // ...
  }
}

// Called each time the server sends an SSL/TLS record to the client.
//-----------------------------------------------------------------------------
void on_server_record(int type, int ver, int *len, char *data)
{
  // Use ChangeCipherSpec to keep track of handshake progress.
  if (type == SSL3_RT_CHANGE_CIPHER_SPEC) {
    ASSERT(handshake == 1,
          "Error: Unexpected ChangeCipherSpec from server.");
    ++handshake;
  }

  // Next Handshake message from server should be its encrypted Finished.
  else if (type == SSL3_RT_HANDSHAKE && handshake == 2) {
    ++handshake;
    INFO(1, "Handshake completed.");
  }

  // If record is application data...
  else if (type == SSL3_RT_APPLICATION_DATA && handshake == 3) {
    if (verbose >= 2)
      dump_data(data, *len);
    // ...
  }

  // If record is error...
  else if (type == SSL3_RT_ALERT && handshake == 3) {
    // ...
  }
}


/*****************************************************************************
 *         /!\ YOU SHOULD NOT MODIFY ANYTHING BELOW THIS POINT! /!\          *
 *****************************************************************************/


/* Global variables.
 *****************************************************************************/

static int mitm_fd     = -1;
static int  cli_fd     = -1;
static int  srv_fd     = -1;
static int in_shutdown = 0;


/* Set up MITM attacker.
 *****************************************************************************/

void mitm_setup(unsigned cli_port)
{
  // Fake server parameters.
  static const char addr[] = "127.0.0.1";

  // Initialize fake server socket.
  mitm_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_LIBC(mitm_fd >= 0, "socket",
              "Error creating fake server socket.");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(cli_port);
  sa.sin_addr.s_addr = inet_addr(addr);

  ASSERT_LIBC(!bind(mitm_fd, (struct sockaddr *)&sa, sizeof(sa)), "bind",
              "Error binding fake server socket to %s:%u.", addr, cli_port);

  ASSERT_LIBC(!listen(mitm_fd, 0), "listen",
              "Error listening on fake server socket.");

  INFO(0, "MITM attacker is ready. Waiting for incoming connections...\n");
}


/* Accept incoming connection from client.
 *****************************************************************************/

void mitm_accept()
{
  // Accept incoming connection to fake server socket.
  struct sockaddr_in sa;
  socklen_t len = sizeof(sa);
  cli_fd = accept(mitm_fd, (struct sockaddr *)&sa, &len);
  ASSERT_LIBC(cli_fd >= 0, "accept",
              "Error accepting incoming connection.");

  INFO(1, "Received client connection from %s:%u.",
       inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
}


/* Establish connection to server.
 *****************************************************************************/

void mitm_connect(unsigned srv_port)
{
  // Server parameters.
  static const char addr[] = "127.0.0.1";

  // Initialize fake client socket and connect to server.
  srv_fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_LIBC(srv_fd >= 0, "socket",
              "Error creating fake client socket.");

  struct sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_port        = htons(srv_port);
  sa.sin_addr.s_addr = inet_addr(addr);

  ASSERT_LIBC(!connect(srv_fd, (struct sockaddr *)&sa, sizeof(sa)), "connect",
              "Error connecting to %s:%u.", addr, srv_port);

  INFO(1, "Connected to server at %s:%u.", addr, srv_port);
}


/* Main MITM loop: process SSL/TLS messages from client or server.
 *****************************************************************************/

void mitm_loop()
{
  fd_set      fd_set;
  int         fd_max  = MAX(srv_fd, cli_fd);
  int         fd[2]   = {  cli_fd,   srv_fd  };
  const char *name[2] = { "client", "server" };
  int         src = -1, dst = -1;
  int         one = 1, zero = 0;

  int         len, rc;
  static char buf[SSL3_RT_MAX_PACKET_SIZE];
  char       *recdata   = buf + SSL3_RT_HEADER_LENGTH;
  int         rectype, recver, reclen;

  // Initialize attacker on new connection.
  on_new_connection();

  // Loop until connection is terminated.
  while (1) {

    // If source is defined, check is more data is available.
    len = 0;
    if (src >= 0) {
      ASSERT_LIBC(!ioctl(fd[src], FIONREAD, &len) != -1, "ioctl",
                  "Error querying %s socket for data.", name[src]);
    }

    // If no more data is available from source, flush write buffer and wait
    // for data to become available, either from client or from server.
    if (!len) {
      // Flush pending writes on destination socket.
      if (dst >= 0) {
        ASSERT_LIBC(!setsockopt(fd[dst], IPPROTO_TCP, TCP_CORK,
                                &zero, sizeof(zero)), "setsockopt",
                    "Error uncorking %s socket.", name[dst]);
      }

      // Wait on sockets.
      FD_ZERO(&fd_set);
      FD_SET(srv_fd, &fd_set);
      FD_SET(cli_fd, &fd_set);
      rc = select(fd_max+1, &fd_set, NULL, NULL, NULL);
      ASSERT_LIBC(rc > 0, "select",
                  "Error waiting on sockets for data.");

      // Assign source and destination sockets.
      src = FD_ISSET(srv_fd, &fd_set) ? 1 : 0;
      dst = 1-src;
    }

    // Receive record header from source.
    len = recv(fd[src], buf, SSL3_RT_HEADER_LENGTH, 0);
    if (len == -1 && errno == ECONNRESET)
      break;
    ASSERT_LIBC(len >= 0, "recv",
                "Error receiving data from %s.", name[src]);
    if (!len)
      break;

    // Parse record header.
    if (len < SSL3_RT_HEADER_LENGTH) {
      FAIL(0, "Error: Truncated SSL/TLS record header.");
      return;
    }

    rectype = *buf;
    recver  = ntohs(*(uint16_t *)(buf+1));
    reclen  = ntohs(*(uint16_t *)(buf+3));

    // Verify record header.
    if (rectype < 0x14 || rectype > 0x18) {
      FAIL(0, "Error: Invalid type 0x%02x in SSL/TLS record header.",
           rectype);
      return;
    }
    if (recver != SSL3_VERSION   && recver != TLS1_VERSION &&
        recver != TLS1_1_VERSION && recver != TLS1_2_VERSION) {
      FAIL(0, "Error: Invalid version 0x%04x in SSL/TLS record header.",
           recver);
      return;
    }
    if (reclen < 0 || reclen > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
      FAIL(0, "Error: Invalid length %d in SSL/TLS record header.", reclen);
      return;
    }

    // Receive record data from source.
    if (reclen) {
      len = recv(fd[src], recdata, reclen, 0);
      if (len == -1 && errno == ECONNRESET)
        break;
      ASSERT_LIBC(len >= 0, "recv",
                  "Error receiving data from %s.", name[src]);
      if (!len)
        break;
      if (len < reclen) {
        FAIL(0, "Error: Truncated SSL/TLS record.");
        return;
      }
    }

    INFO(2, "Parsed %s record (type: 0x%02x, length: %3d bytes)"
            " from %s to %s.",
            recver == SSL3_VERSION   ? SSL_TXT_SSLV3   :
            recver == TLS1_VERSION   ? SSL_TXT_TLSV1   :
            recver == TLS1_1_VERSION ? SSL_TXT_TLSV1_1 :
                                       SSL_TXT_TLSV1_2,
            rectype, reclen, name[src], name[dst]);
    if (verbose >= 3)
      dump_data(recdata, reclen);

    // Call record intercepting function according to source.
    if (!src)
      on_client_record(rectype, recver, &reclen, recdata);
    else                                       
      on_server_record(rectype, recver, &reclen, recdata);
    if (reclen < 0)
      continue;

    // Update record length, if changed.
    *(uint16_t *)(buf+3) = htons(reclen);

    // Delay writes on destination socket.
    ASSERT_LIBC(!setsockopt(fd[dst], IPPROTO_TCP, TCP_CORK,
                            &one, sizeof(one)), "setsockopt",
                "Error corking %s socket.", name[dst]);

    // Forward record (header and data) to destination.
    len = SSL3_RT_HEADER_LENGTH + reclen;
    rc  = -1;
    for (const char *p = buf; len && rc; p += rc, len -= rc) {
      rc = send(fd[dst], p, len, 0);
      ASSERT_LIBC(rc >= 0, "send",
                  "Error sending data to %s.", name[dst]);
    }
    if (len)
      break;
  }

  INFO(1, "Connection was terminated by %s.", name[src]);
}


/* Close connections to client and server.
 *****************************************************************************/

void mitm_close()
{
  // Close client-side socket.
  if (cli_fd >= 0) {
    fd_set         fd_set;
    struct timeval timeout = { .tv_sec = 1 };
    FD_ZERO(&fd_set);
    FD_SET(cli_fd, &fd_set);
    int rc = select(cli_fd+1, &fd_set, NULL, &fd_set, &timeout);
    ASSERT_LIBC(rc >= 0, "select",
                "Error waiting on client-side socket.");
    if (!rc)
      FAIL(0, "Timeout waiting for client to terminate connection.");

    ASSERT_LIBC(!close(cli_fd), "close",
                "Error closing client socket.");
    cli_fd = -1;
    INFO(1, "Client-side connection closed.");
  }

  // Close server-side socket.
  if (srv_fd >= 0) {
    ASSERT_LIBC(!close(srv_fd), "close",
                "Error closing server-side socket.");
    srv_fd = -1;
    INFO(1, "Server-side connection closed.");
  }

  if (verbose >= 1)
    fprintf(stderr, "\n");
}


/* Shut down MITM attacker and clean up.
 *****************************************************************************/

void mitm_shutdown()
{
  if (in_shutdown)
    return;
  in_shutdown = 1;

  // Close connections with client and server, if any.
  if (cli_fd >= 0 || srv_fd >=0)
    mitm_close();

  // Close fake server socket.
  if (mitm_fd >= 0) {
    ASSERT_LIBC(!close(mitm_fd), "close",
                "Error closing fake server socket.");
    mitm_fd = -1;
  }
}


/* Signal handler.
 *****************************************************************************/

void sig_handler(int sig)
{
  if (sig == SIGINT || sig == SIGTERM)
    ALERT(0, "Interruption detected. Exiting...");
  else if (sig == SIGPIPE)
    ALERT(0, "Lost connection to client or server. Exiting...");
  else
    FAIL(0, "Aborting...");

  mitm_shutdown();

  exit(sig == SIGABRT ? EXIT_FAILURE : EXIT_SUCCESS);
}


/* Program entry point.
 *****************************************************************************/

static const char usage[] = "Usage: mitm [options] <cli-port> <srv-port>\n"
                            "\n"
                            "  <cli-port>  Client-side port number\n"
                            "  <srv-port>  Server-side port number\n"
                            "\n"
                            "Options:\n"
                            "  -q          Decrease verbosity level\n"
                            "  -v          Increase verbosity level\n";

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
  ASSERT(argc <= 2, "Too many parameters.\n%s",             usage);
  ASSERT(argc >= 1, "Missing client-side port number.\n%s", usage);
  ASSERT(argc >= 2, "Missing server-side port number.\n%s", usage);

  unsigned cli_port = atoi(argv[0]);
  unsigned srv_port = atoi(argv[1]);

  // Set up MITM attacker.
  mitm_setup(cli_port);

  // Process incoming connections from clients.
  while (1) {
    mitm_accept();
    mitm_connect(srv_port);
    mitm_loop();
    mitm_close();
  }

  // Shut down MITM attacker and clean up.
  mitm_shutdown();

  return EXIT_SUCCESS;
}
