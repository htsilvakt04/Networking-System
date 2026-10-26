# Debug test: the server sends a ~1.8KB HTTP response to the client.
# The client is the student socket, so this exercises rx() and rx_queue.
# With drop_first=True, the first data segment is dropped once on the way to
# the client, so segment 2 arrives first and has to wait in rx_queue until
# the server retransmits segment 1.

from tcpip.recoco_sockets import SimpleReSocketApp
from pox.lib.recoco import task_function
from pox.core import core
from tcpip.modulo_math import *
from cs168p2.tests import Tester
from tcpip.tcp_sockets import TXWindow
import random
from ast import literal_eval

TOTAL_SIZE = 1800

def make_http_response (total_size):
  head = ("HTTP/1.1 200 OK\r\n"
          "Content-Type: text/plain\r\n"
          "Content-Length: {0:04d}\r\n"
          "\r\n")
  body_len = total_size - len(head.format(0))
  body = ("abcdefghij" * (body_len // 10 + 1))[:body_len]
  return head.format(body_len) + body

HTTP_RESPONSE_DATA = make_http_response(TOTAL_SIZE)

class RXApp (SimpleReSocketApp):
  # Missing rx_buffer = b''
  @task_function
  def _on_connected (self):
    while True:
      d = yield self.sock.recv(1, at_least=True)
      if not d: break
      self.rx_buffer += d

def launch (log_name="http_response", run_time=10, drop_first=True,
            server_isn=None):
  drop_first = str(drop_first).lower() in ("1", "true", "yes")

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

    # Server (POX socket) sends the response as soon as the client connects
    sapp = s1.netcat(port=1000, listen=True,
                     child_kwargs=dict(data=HTTP_RESPONSE_DATA))
    capp = c1._new_resocket_app(RXApp, ip=s1.netdev.ip_addr, port=1000, delay=0.5)
    capp.rx_buffer = b''

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
      rcv_nxt = csock.rcv.nxt if csock and getattr(csock, "rcv", None) else None

      pkts.append((src, parsed, payload))
      log.info("#%d %s -> %s  seq=%s ack=%s flags=%s len=%d  client_state=%s client_rcv.nxt=%s",
               len(pkts), src, "server" if src == "client" else "client",
               parsed.seq, parsed.ack, "|".join(flags), len(payload),
               state, rcv_nxt)
      if payload:
        log.info("    first 60 bytes: %r", bytes(payload[:60]))

    r1.stack.add_packet_capture("*", on_cap, ip_only=True)

    class drop_first_data_once (object):
      def __init__ (self):
        self.dropped = False

      def __call__ (self, dev, packet):
        tcp = packet.find("tcp")
        # only drop a server data segment, and only once
        if self.dropped or not tcp or not tcp.payload or tcp.srcport != 1000:
          return False
        self.dropped = True
        log.info("DROPPED server segment seq=%s (client will see the next one first)", tcp.seq)
        return True

    if drop_first:
      topo.get_wire(r1,c1).drop_conditions.append(drop_first_data_once())

    def do_score ():
      data_pkts = [p for p in pkts if p[0] == "server" and p[2]]
      log.info("server sent %d data segments (incl. retransmits), sizes=%s",
               len(data_pkts), [len(p[2]) for p in data_pkts])

      tester.expect_eq(HTTP_RESPONSE_DATA.encode('ascii'), capp.rx_buffer,
                       "client received the whole HTTP response in order")

    def on_end ():
      try:
        do_score()
        tester.finish()
      except Exception:
        log.exception("Exception during scoring")
      core.quit()

    tm.set_timer_at(float(run_time), on_end)

  core.call_when_ready(setup, ["sim_topo"], "test")
