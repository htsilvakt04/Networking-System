# Debug test: client sends a ~1.8KB HTTP POST request to the server.
# With the default MTU (1500 -> MSS 1380) this should be split into 2 segments.
# The server uses Content-Length to know when the whole request has arrived,
# then replies "200 OK". The client reads the response the same way, then
# closes the connection.
# Every TCP segment seen at r1 is logged so you can inspect each packet.

from tcpip.recoco_sockets import SimpleReSocketApp
from pox.lib.recoco import task_function
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Tester
from tcpip.tcp_sockets import TXWindow
import random
import re
from ast import literal_eval

TOTAL_SIZE = 1800

def make_http_post (total_size):
  head = ("POST /upload HTTP/1.1\r\n"
          "Host: s1\r\n"
          "Content-Type: text/plain\r\n"
          "Content-Length: {0:04d}\r\n"
          "\r\n")
  body_len = total_size - len(head.format(0))
  body = ("0123456789" * (body_len // 10 + 1))[:body_len]
  return head.format(body_len) + body

def make_http_200 (body):
  return ("HTTP/1.1 200 OK\r\n"
          "Content-Type: text/plain\r\n"
          "Content-Length: {0}\r\n"
          "\r\n"
          "{1}").format(len(body), body)

HTTP_REQUEST_DATA = make_http_post(TOTAL_SIZE)

class HTTPMessageReader (object):
  """
  Collects bytes from recv() and tells you when one full HTTP message is here.

  TCP only gives us a stream of bytes, so the message boundary comes from HTTP:
    1. read until "\r\n\r\n" -> the header is complete
    2. read Content-Length from the header
    3. read until we have Content-Length body bytes
  """
  def __init__ (self, log, who):
    self.log = log
    self.who = who
    self.buf = b''
    self.header = None
    self.body_len = None

  @property
  def body (self):
    return self.buf[len(self.header) + 4:] if self.header is not None else b''

  @property
  def message (self):
    return self.buf[:len(self.header) + 4 + self.body_len]

  def feed (self, d):
    """Add bytes from one recv(). Returns True once the whole message is here."""
    self.buf += d
    self.log.info("[%s] recv() returned %d bytes (have %d so far)",
                  self.who, len(d), len(self.buf))

    if self.header is None:
      if b'\r\n\r\n' not in self.buf:
        return False
      self.header = self.buf.split(b'\r\n\r\n', 1)[0]
      m = re.search(br'Content-Length:\s*(\d+)', self.header, re.IGNORECASE)
      self.body_len = int(m.group(1)) if m else 0
      self.log.info("[%s] header complete (%d bytes), Content-Length=%d",
                    self.who, len(self.header) + 4, self.body_len)

    self.log.info("[%s] body %d/%d bytes", self.who, len(self.body), self.body_len)
    return len(self.body) >= self.body_len

def usock_send (usock, data):
  # The student socket's send() takes a str; POX's may want bytes
  try:
    return usock.send(data)
  except (TypeError, AttributeError):
    return usock.send(data.encode('ascii'))

class HTTPServerApp (SimpleReSocketApp):
  requests = []   # full requests the server received
  @task_function
  def _on_connected (self):
    log = core.getLogger("http_post")
    reader = HTTPMessageReader(log, "server")

    # Read until Content-Length says the request is complete
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d:
        log.warn("[server] connection closed before the request was complete")
        return
      if reader.feed(d):
        break

    self.requests.append(reader.message)
    log.info("[server] full request received -> sending 200 OK")

    response = make_http_200("received %d bytes" % (reader.body_len,))
    usock_send(self.sock.usock, response)

    # Wait for the client to close, then close our side
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d: break
    log.info("[server] client closed -> closing")
    self.sock.close()

class HTTPPostApp (SimpleReSocketApp):
  responses = []  # full responses the client received
  @task_function
  def _on_connected (self):
    log = core.getLogger("http_post")

    # One send() call; your maybe_send() decides how to split it into segments
    n = self.sock.usock.send(HTTP_REQUEST_DATA)
    log.info("[client] send() with %s bytes, accepted %s", len(HTTP_REQUEST_DATA), n)

    # Read the response; your rx() fills rx_data, recv() takes from it
    reader = HTTPMessageReader(log, "client")
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d:
        log.warn("[client] connection closed before the response was complete")
        return
      if reader.feed(d):
        break

    self.responses.append(reader.message)
    log.info("[client] full response received: %r -> closing", reader.message)
    self.sock.close()

def launch (log_name="http_post", run_time=5, server_isn=None):
  def setup ():
    log = core.getLogger(log_name)
    tester = Tester(log)
    topo = core.sim_topo

    if server_isn is None:
      TXWindow.generate_isn = lambda _: random.randint(1000,100000)
    else:
      TXWindow.generate_isn = lambda _: literal_eval(server_isn)

    def get_client_socket ():
      try:
        return next(iter(c1.stack.socket_manager.peered.values()))
      except Exception:
        return None

    c1 = topo.get_node("c1")
    s1 = topo.get_node("s1")
    r1 = topo.get_node("r1")
    tm = topo.time

    sapp = s1._new_resocket_app(HTTPServerApp, port=1000, listen=True)
    capp = c1._new_resocket_app(HTTPPostApp, ip=s1.netdev.ip_addr, port=1000, delay=0.5)

    pkts = []

    def on_cap (e):
      parsed = e.parsed
      if not parsed: return
      parsed = parsed.find("tcp")
      if not parsed: return

      payload = parsed.payload
      if not isinstance(payload, (bytes, bytearray)):
        payload = payload.pack() if payload else b''

      src = "client" if parsed.srcport != 1000 else "server"
      flags = [f for f in ("SYN","ACK","FIN","PSH","RST") if getattr(parsed, f)]
      csock = get_client_socket()
      state = csock.state if csock else None

      pkts.append((src, parsed, payload))
      log.info("#%d %s -> %s  seq=%s ack=%s flags=%s win=%s len=%d  client_state=%s",
               len(pkts), src, "server" if src == "client" else "client",
               parsed.seq, parsed.ack, "|".join(flags), parsed.win,
               len(payload), state)
      if payload:
        log.info("    first 80 bytes: %r", bytes(payload[:80]))
        log.info("    last  40 bytes: %r", bytes(payload[-40:]))

    r1.stack.add_packet_capture("*", on_cap, ip_only=True)

    def do_score ():
      data_pkts = [p for p in pkts if p[0] == "client" and p[2]]
      log.info("client sent %d data segments, sizes=%s",
               len(data_pkts), [len(p[2]) for p in data_pkts])

      expected_response = make_http_200("received %d bytes" % (TOTAL_SIZE - HTTP_REQUEST_DATA.index("\r\n\r\n") - 4,))

      tester.expect_eq(HTTP_REQUEST_DATA.encode('ascii'),
                       HTTPServerApp.requests[0] if HTTPServerApp.requests else None,
                       "server received the whole HTTP POST")
      tester.expect_eq(2, len(data_pkts), "request split into 2 data segments")
      tester.expect_eq(expected_response.encode('ascii'),
                       HTTPPostApp.responses[0] if HTTPPostApp.responses else None,
                       "client received 200 OK")

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()

    tm.set_timer_at(float(run_time), on_end)

  core.call_when_ready(setup, ["sim_topo"], "test")
