import re
import os
import asyncio
import ipaddress
import inspect
import typing
import logging
import collections.abc
from functools import cache, wraps, partial
from mitmproxy.proxy.server_hooks import ServerConnectionHookData
from mitmproxy.dns import DNSFlow, Question
import mitmproxy.flowfilter
import mitmproxy.flow
import mitmproxy.dns
import mitmproxy.proxy

DNS_CACHE = {}

@cache
def cached(fn, *args):
    return fn(*args)

def only(*classes):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args):
            if isinstance(args[-1], classes):
                return fn(*args)
        return wrapped
    return decorator
only = partial(cached, only)

class Matchers:

    @only(DNSFlow, Question)
    def dns(data):
        return True

    @only(DNSFlow, Question)
    def dnst(regex: str, data):
        if isinstance(data, DNSFlow):
            return any(Matchers.dnst(regex, q) for q in data.request.questions)
        return re.search(regex, mitmproxy.dns.types.to_str(data.type), re.IGNORECASE)

    @only(mitmproxy.flow.Flow, Question)
    def d(regex: str, data):

        if isinstance(data, DNSFlow):
            return any(Matchers.d(regex, q) for q in data.request.questions)

        regex = re.compile(regex, re.IGNORECASE)

        if isinstance(data, Question):
            return regex.search(data.name)

        if data.client_conn.tls and data.client_conn.sni is not None:
            return regex.search(data.client_conn.sni)
        elif data.server_conn.address and (names := DNS_CACHE.get(data.server_conn.address[0])):
            # we'll grab it from the dns cache
            return any(regex.search(n) for n in names)

def AND(nodes, data):
    return all(n(data) for n in nodes)

def OR(nodes, data):
    return any(n(data) for n in nodes)

def NOT(node, data):
    return not node(data)

def filter_unary(cls, data):
    return cached(cls)(data)
def filter_rex(cls, regex: str, data):
    return cached(cls, regex)(data)
def filter_int(cls, value: int, data):
    return cached(cls, value)(data)

for collection, func in [
    (mitmproxy.flowfilter.filter_unary, filter_unary),
    (mitmproxy.flowfilter.filter_rex, filter_rex),
    (mitmproxy.flowfilter.filter_int, filter_int),
]:
    for f in collection:
        if not hasattr(Matchers, f.code):
            setattr(Matchers, f.code, partial(func, f))

ASK_LOCK = asyncio.Lock()

class Actions:

    async def block(data):
        if isinstance(data, DNSFlow):
            # dns flows are not killable
            data.response = data.request.fail(mitmproxy.dns.response_codes.NXDOMAIN)
        elif isinstance(data, mitmproxy.flow.Flow):
            data.server_conn.error = 'blocked'
            data.kill()
        elif isinstance(data, ServerConnectionHookData):
            data.server.error = 'blocked'
        elif isinstance(data, Question):
            data.blocked = True
        else:
            raise NotImplementedError(data)

    async def allow(data):
        pass

    async def ask(data):
        if isinstance(data, DNSFlow):
            # skip, you'll get asked later for each question
            return
        elif isinstance(data, Question):
            descr = f'DNS ({mitmproxy.dns.types.to_str(data.type)}) {data.name}'
        elif isinstance(data, mitmproxy.http.HTTPFlow):
            descr = f'HTTP {data.request.method.upper()} to {data.request.pretty_url}'
        elif isinstance(data, mitmproxy.flow.Flow):
            descr = f'{type(data).__name__.removesuffix('Flow')} to {data.server_conn.address[0]}:{data.server_conn.address[1]}'
        else:
            raise NotImplementedError(data)

        async with ASK_LOCK:
            if mitmproxy.ctx.options.nsb_ask_cmd:
                # execute custom ask command with description as $1
                proc = await asyncio.create_subprocess_exec('bash', '-c', mitmproxy.ctx.options.nsb_ask_cmd, '--', descr)
                if await proc.wait() == 0:
                    return await Actions.allow(data)
                else:
                    return await Actions.block(data)

            else:
                # Default terminal-based prompt
                msg = f'>>> {descr}\n>>> (a)llow / (b)lock? '
                while True:
                    answer = await asyncio.get_running_loop().run_in_executor(None, input, msg)
                    match answer.strip().lower():
                        case 'a'|'allow':
                            return await Actions.allow(data)
                        case 'b'|'block':
                            return await Actions.block(data)

class Parser:
    END_REGEX = re.compile('[&|]')
    END_AND_BRACKET_REGEX = re.compile('[&|)]')
    WORD_REGEX = re.compile(r'''(?!~)(\\.|\S)+|'(\\.|[^'])*'|"(\\.|[^"])*"''')
    NUM_REGEX = re.compile(r'\d+')
    OPS = {k: v for k, v in vars(Matchers).items() if not k.startswith('_')}
    OPS_REGEX = re.compile(r'([!(]' + ''.join(rf'|~{k}\b' for k in OPS.keys()) + '|' + WORD_REGEX.pattern + ')')

    def __init__(self, string: str):
        self.string = string.lstrip()

    def get_one(self, regex: re.Pattern):
        if match := regex.match(self.string):
            self.string = self.string[match.end():].lstrip()
            return match
        raise ValueError(self.string)

    def parse_word(self, regex=None):
        regex = regex or self.get_one(self.WORD_REGEX).group(0)
        if regex[0] in ('"', "'"):
            regex = regex[1:-1]
        return re.sub(r'\\(.)', r'\1', regex)

    def parse_number(self):
        return int(self.get_one(self.NUM_REGEX).group(0))

    def parse_op(self):
        match = self.get_one(self.OPS_REGEX).group(0)

        if match == '(':
            return self.parse(allow_closing_bracket=True)
        elif match == '!':
            return partial(NOT, self.parse_op())
        elif match.startswith('~'):
            func = self.OPS[match.removeprefix('~')]
            params = list(inspect.signature(func).parameters.items())[:-1] # except the last
            if not params:
                return func
            elif params[0][1].annotation is str:
                return partial(func, self.parse_word())
            elif params[0][1].annotation is int:
                return partial(func, self.parse_number())
            else:
                raise NotImplementedError(params[0][1].annotation)
        else:
            # match against url as fallback
            return partial(Matchers.u, self.parse_word(match))

    def parse(self, allow_closing_bracket=False):
        func = AND
        args = [self.parse_op()]
        while self.string:
            match = self.get_one(self.END_AND_BRACKET_REGEX if allow_closing_bracket else self.END_REGEX).group(0)
            if match == ')':
                break
            newfunc = {'&': AND, '|': OR}[match]
            if func is not newfunc and len(args) > 1:
                args = [partial(func, args)]
            func = newfunc
            args.append(self.parse_op())

        if len(args) == 1:
            return args[0]
        return partial(func, args)

class Addon:
    def __init__(self):
        self.specs = []

    async def apply_specs(self, data):
        try:
            if mitmproxy.ctx.options.nsb_block_direct_ip and self.is_direct_ip(data):
                return await Actions.block(data)

            if mitmproxy.ctx.options.nsb_block_domain_fronting and self.is_domain_fronting(data):
                return await Actions.block(data)

            for action, spec in self.specs:
                if spec(data):
                    return await action(data)
        # nothing matched, block by default
        except Exception:
            await Actions.block(data)
            raise
        await Actions.block(data)

    def is_direct_ip(self, data):
        return isinstance(data, mitmproxy.flow.Flow) and not isinstance(data, DNSFlow) and data.server_conn.address[0] not in DNS_CACHE

    def is_domain_fronting(self, data):
        if not isinstance(data, mitmproxy.flow.Flow) or isinstance(data, DNSFlow):
            return False

        if not (dns := DNS_CACHE.get(data.server_conn.address[0])):
            return True

        sni = None
        if data.client_conn.tls and not (sni := data.client_conn.sni):
            return True

        header = None
        if isinstance(data, mitmproxy.http.HTTPFlow) and not data.client_conn.tls and not (header := data.request.headers.get('host')):
            return True

        return (sni is not None and sni not in dns) or (header is not None and header not in dns)

    def load(self, loader: mitmproxy.addonmanager.Loader):
        '''Called when an addon is first loaded. This event receives a Loader object, which contains methods for adding options and commands. This method is where the addon configures itself.'''
        loader.add_option("nsb_spec", collections.abc.Sequence[str], [], 'nsb filter spec')
        loader.add_option("nsb_readiness_fd", typing.Optional[int], None, 'nsb readiness fd (internal use)')
        loader.add_option("nsb_block_direct_ip", bool, True, 'block direct ip access not resolved via dns')
        loader.add_option("nsb_block_domain_fronting", bool, True, 'block domain fronting (mismatched dns/sni/host)')
        loader.add_option("nsb_redirect_all_dns", bool, True, 'redirect all DNS to the system resolver (including to e.g. 1.1.1.1)')
        loader.add_option("nsb_ask_cmd", str, "", "shell snippet to run for the 'ask' action")

    def running(self):
        '''Called when the proxy is completely up and running. At this point, you can expect all addons to be loaded and all options to be set.'''
        fd = mitmproxy.ctx.options.nsb_readiness_fd
        if fd is not None:
            os.write(fd, b'1')
            os.close(fd)
            mitmproxy.ctx.options.nsb_readiness_fd = None

    def add_spec(self, string: str):
        try:
            action, _, spec = string.partition(':')
            if action == 'include':
                with open(spec) as file:
                    for line in file:
                        self.add_spec(line)
            else:
                action = getattr(Actions, action)
                spec = Parser(spec).parse()
                self.specs.append((action, spec))
        except Exception:
            logging.warning('Failed to parse spec %s', string)
            raise

    def configure(self, updated: set[str]):
        '''Called when configuration changes. The updated argument is a set-like object containing the keys of all changed options. This event is called during startup with all options in the updated set.'''

        if "nsb_spec" in updated:
            self.specs.clear()
            try:
                for spec in mitmproxy.ctx.options.nsb_spec:
                    self.add_spec(spec)
            except Exception:
                pass

    def done(self):
        '''Called when the addon shuts down, either by being removed from the mitmproxy instance, or when mitmproxy itself shuts down. On shutdown, this event is called after the event loop is terminated, guaranteeing that it will be the final event an addon sees. Note that log handlers are shut down at this point, so calls to log functions will produce no output.'''
        '''Connection Events'''

    def client_connected(self, client: mitmproxy.connection.Client):
        '''A client has connected to mitmproxy. Note that a connection can correspond to multiple HTTP requests.'''
        '''Setting client.error kills the connection.'''

    def client_disconnected(self, client: mitmproxy.connection.Client):
        '''A client connection has been closed (either by us or the client).'''

    async def server_connect(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData):
        '''Mitmproxy is about to connect to a server. Note that a connection can correspond to multiple requests.'''
        '''Setting data.server.error kills the connection.'''
        #  print(f'''DEBUG(jawed) \t{data = }''', file=sys.__stderr__)
        # await self.apply_specs(data)

    def server_connected(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData):
        '''Mitmproxy has connected to a server.'''
        #  print(f'''DEBUG(iffier)\t{data = }''', file=sys.__stderr__)

    def server_disconnected(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData):
        '''A server connection has been closed (either by us or the server).'''

    def server_connect_error(self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData):
        '''Mitmproxy failed to connect to a server.'''
        '''Every server connection will receive either a server_connected or a server_connect_error event, but not both.'''

    def requestheaders(self, flow: mitmproxy.http.HTTPFlow):
        '''HTTP request headers were successfully read. At this point, the body is empty.'''

    async def request(self, flow: mitmproxy.http.HTTPFlow):
        '''The full HTTP request has been read.'''
        '''Note: If request streaming is active, this event fires after the entire body has been streamed. HTTP trailers, if present, have not been transmitted to the server yet and can still be modified. Enabling streaming may cause unexpected event sequences: For example, response may now occur before request because the server replied with "413 Payload Too Large" during upload.'''
        await self.apply_specs(flow)

    def responseheaders(self, flow: mitmproxy.http.HTTPFlow):
        '''HTTP response headers were successfully read. At this point, the body is empty.'''

    def response(self, flow: mitmproxy.http.HTTPFlow):
        '''The full HTTP response has been read.'''
        '''Note: If response streaming is active, this event fires after the entire body has been streamed. HTTP trailers, if present, have not been transmitted to the client yet and can still be modified.'''

    def error(self, flow: mitmproxy.http.HTTPFlow):
        '''An HTTP error has occurred, e.g. invalid server responses, or interrupted connections. This is distinct from a valid server HTTP error response, which is simply a response with an HTTP error code.'''
        '''Every flow will receive either an error or an response event, but not both.'''

    def http_connect(self, flow: mitmproxy.http.HTTPFlow):
        '''An HTTP CONNECT request was received. This event can be ignored for most practical purposes.'''
        '''This event only occurs in regular and upstream proxy modes when the client instructs mitmproxy to open a connection to an upstream host. Setting a non 2xx response on the flow will return the response to the client and abort the connection.'''
        '''CONNECT requests are HTTP proxy instructions for mitmproxy itself and not forwarded. They do not generate the usual HTTP handler events, but all requests going over the newly opened connection will.'''

    def http_connect_upstream(self, flow: mitmproxy.http.HTTPFlow):
        '''An HTTP CONNECT request is about to be sent to an upstream proxy. This event can be ignored for most practical purposes.'''
        '''This event can be used to set custom authentication headers for upstream proxies.'''
        '''CONNECT requests do not generate the usual HTTP handler events, but all requests going over the newly opened connection will.'''

    def http_connected(self, flow: mitmproxy.http.HTTPFlow):
        '''HTTP CONNECT was successful'''
        '''This may fire before an upstream connection has been established if connection_strategy is set to lazy (self, default)'''

    def http_connect_error(self, flow: mitmproxy.http.HTTPFlow):
        '''HTTP CONNECT has failed. This can happen when the upstream server is unreachable or proxy authentication is required. In contrast to the error hook, flow.error is not guaranteed to be set.'''

    async def dns_request(self, flow: mitmproxy.dns.DNSFlow):
        '''A DNS query has been received.'''
        await self.apply_specs(flow)
        if mitmproxy.ctx.options.nsb_redirect_all_dns:
            if not isinstance(flow.client_conn.proxy_mode, mitmproxy.proxy.mode_specs.WireGuardMode):
                flow.client_conn.proxy_mode = cached(mitmproxy.proxy.mode_specs.WireGuardMode, '', '', '', '')
            flow.server_conn.address = ('10.0.0.53', 53)
        for q in flow.request.questions:
            await self.apply_specs(q)
        questions = [q for q in flow.request.questions if not getattr(q, 'blocked', None)]
        if questions:
            flow.request.questions = questions
        else:
            flow.response = flow.request.fail(mitmproxy.dns.response_codes.NXDOMAIN)

    def dns_response(self, flow: mitmproxy.dns.DNSFlow):
        '''A DNS response has been received or set.'''
        for answer in flow.response.answers:
            if answer.type in (mitmproxy.dns.types.A, mitmproxy.dns.types.AAAA):
                ip = str(ipaddress.ip_address(answer.data))
                DNS_CACHE.setdefault(ip, set()).add(answer.name)

    def dns_error(self, flow: mitmproxy.dns.DNSFlow):
        '''A DNS error has occurred.'''

    async def tcp_start(self, flow: mitmproxy.tcp.TCPFlow):
        '''A TCP connection has started.'''
        await self.apply_specs(flow)

    def tcp_message(self, flow: mitmproxy.tcp.TCPFlow):
        '''A TCP connection has received a message. The most recent message will be flow.messages[-1]. The message is user-modifiable.'''

    def tcp_end(self, flow: mitmproxy.tcp.TCPFlow):
        '''A TCP connection has ended.'''

    def tcp_error(self, flow: mitmproxy.tcp.TCPFlow):
        '''A TCP error has occurred.'''
        '''Every TCP flow will receive either a tcp_error or a tcp_end event, but not both.'''

    async def udp_start(self, flow: mitmproxy.udp.UDPFlow):
        '''A UDP connection has started.'''
        await self.apply_specs(flow)

    def udp_message(self, flow: mitmproxy.udp.UDPFlow):
        '''A UDP connection has received a message. The most recent message will be flow.messages[-1]. The message is user-modifiable.'''

    def udp_end(self, flow: mitmproxy.udp.UDPFlow):
        '''A UDP connection has ended.'''

    def udp_error(self, flow: mitmproxy.udp.UDPFlow):
        '''A UDP error has occurred.'''
        '''Every UDP flow will receive either a udp_error or a udp_end event, but not both.'''

    def quic_start_client(self, data: mitmproxy.proxy.layers.quic._hooks.QuicTlsData):
        '''TLS negotiation between mitmproxy and a client over QUIC is about to start.'''
        '''An addon is expected to initialize data.settings. (self, by default, this is done by mitmproxy.addons.tlsconfig)'''

    def quic_start_server(self, data: mitmproxy.proxy.layers.quic._hooks.QuicTlsData):
        '''TLS negotiation between mitmproxy and a server over QUIC is about to start.'''
        '''An addon is expected to initialize data.settings. (self, by default, this is done by mitmproxy.addons.tlsconfig)'''

    def tls_clienthello(self, data: mitmproxy.tls.ClientHelloData):
        '''Mitmproxy has received a TLS ClientHello message.'''
        '''This hook decides whether a server connection is needed to negotiate TLS with the client (data.establish_server_tls_first)'''

    def tls_start_client(self, data: mitmproxy.tls.TlsData):
        '''TLS negotation between mitmproxy and a client is about to start.'''
        '''An addon is expected to initialize data.ssl_conn. (self, by default, this is done by mitmproxy.addons.tlsconfig)'''

    def tls_start_server(self, data: mitmproxy.tls.TlsData):
        '''TLS negotation between mitmproxy and a server is about to start.'''
        '''An addon is expected to initialize data.ssl_conn. (self, by default, this is done by mitmproxy.addons.tlsconfig)'''

    def tls_established_client(self, data: mitmproxy.tls.TlsData):
        '''The TLS handshake with the client has been completed successfully.'''

    def tls_established_server(self, data: mitmproxy.tls.TlsData):
        '''The TLS handshake with the server has been completed successfully.'''

    def tls_failed_client(self, data: mitmproxy.tls.TlsData):
        '''The TLS handshake with the client has failed.'''

    def tls_failed_server(self, data: mitmproxy.tls.TlsData):
        '''The TLS handshake with the server has failed.'''

    def websocket_start(self, flow: mitmproxy.http.HTTPFlow):
        '''A WebSocket connection has commenced.'''

    def websocket_message(self, flow: mitmproxy.http.HTTPFlow):
        '''Called when a WebSocket message is received from the client or server. The most recent message will be flow.messages[-1]. The message is user-modifiable. Currently there are two types of messages, corresponding to the BINARY and TEXT frame types.'''

    def websocket_end(self, flow: mitmproxy.http.HTTPFlow):
        '''A WebSocket connection has ended. You can check flow.websocket.close_code to determine why it ended.'''

addons = [Addon()]
