# nsb

Ad-hoc network sandboxing tool.

Run your command in a network namespace and funnel the network traffic
through [mitmproxy](https://www.mitmproxy.org/) with configurable allow/block rules.

## Installation + quick usage

You need these dependencies
* Linux with user namespacing enabled
* python3
* [mitmdump](https://docs.mitmproxy.org/stable/overview/installation/)
* [pasta](https://passt.top/passt/about/#availability) (if you have podman, you are probably already using this)

Then clone/download this repo and run something like:
```bash
./nsb --set='nsb_spec=allow: ~d github.com' bash
```
You will now be in a bash shell. If you run something like `curl github.com` it should work, but something like `curl google.com` will fail.

## Other sandboxing

`nsb` concerns itself with networking *only* and in particular *provides no effective filesystem sandboxing*.
In particular this means that untrusted applications may be able to *modify* `nsb` and its code and effectively weaken or disable it.
This will not be fixed.
Instead you are **strongly** recommended to pair `nsb` with something that *does* provide
that extra sandboxing for you, for example [bubblewrap](https://github.com/containers/bubblewrap).

## Usage

`nsb` can be run as follows:
```
nsb [OPTIONS] [--] COMMAND...
```
`nsb` takes a handful of flags, but any unknown flags are passed to `mitmdump`.

It loads the `./mitm.py` addon which does the actual allowing/blocking, and takes the options:
* `nsb_spec` - list of allow/block rules
* `nsb_allow_direct_ip` - list of `IP[/MASK]` to allow direct access to IPs that do not have a previous corresponding DNS lookup, otherwise it is blocked
* `nsb_block_domain_fronting` - block HTTP(s) access where any of the DNS, SNI or host header do not match (enabled by default)
* `nsb_redirect_all_dns` - redirect all DNS to the system resolver i.e. preventing processes from trying to query DNS servers directly e.g. `dig @1.1.1.1 ...` (enabled by default)
* `nsb_ask_cmd` - shell snippet to run for the `ask` action

### `nsb_spec`

The option you will be using most often is `nsb_spec`, it lets you specify the list of allow/block rules.
You can specify multiple rules and they will be applied in order e.g. `./nsb --set='nsb_spec=allow: ~d github.com' --set='nsb_spec=allow: ~d google.com' ...`.
The hardcoded last rule blocks everything. The first rule that matches a request is used, any following rules will be ignored.

The format of a spec is `ACTION:FILTER`, where `ACTION` is one of:
* `allow` - allow the request through
* `block` - terminate the request/connection, or for DNS queries returns NXDOMAIN
* `ask` - asks whether you want to allow or block. `ask` is quite clunky to use, in general you should avoid it.
* `include` - treat `FILTER` as a path to a file to load more specs from, e.g. `./nsb --set='nsb_spec=include:/path/to/file' ...`

and the `FILTER` follows the same syntax as described [here](https://docs.mitmproxy.org/stable/concepts/filters/) with the following modifications:
* there is an additional `~dnst REGEX` expression that allows you to filter by DNS question type (i.e. A, TXT, MX etc).
* there is an additional `~dstip IP[/MASK]` expression that allows you to filter destination IP e.g. `~dstip 10.0.0.0/8`
    * to match on the port you can use `~dst :1234$`
* there is an additional `~proto REGEX` expression that allows you to filter on the protocol (TCP or UDP)
    * this is *different* from using the `~tcp` or `~udp` filters which match *otherwise unrecognised* TCP/UDP flows,
        e.g. an HTTP request will *not* match `~tcp` but *will* match `~proto tcp`
        whereas an SSH connection *will also* match `~tcp` (because SSH is not recognised by mitmproxy)
* there is an additional `~quic` expression that allows you match QUIC network

Note that all regex matches are case insensitive and done by [re.search](https://docs.python.org/3/library/re.html#re.search)!
If you want exact matches you should use `^` and `$` anchors.

> You may try to do something like `./nsb --set='nsb_spec=allow: ~d github.com & ~m get' curl github.com` to allow only GET requests to github.com
> but discover it doesn't work! This is because DNS will be blocked as it will not match the `~m get` part.
> Instead do: `./nsb --set='nsb_spec=allow: ~d github.com & (~m get | ~dns)' curl github.com`

### Run mitmproxy separately

Usually `nsb` runs your command and `mitmdump` together, but you can split it up:
1. Run `./nsb --only-mitmdump` (which really just does something like `mitmdump --set=connection_strategy=lazy --scripts=mitm.py --mode=wireguard`) and note the port
1. Then run `./nsb --no-mitmdump --wg-port PORT ...`

This allows you to run them in separate terminals (which also works better with the `ask` action), or to keep one long-running `mitmdump` instance.
Or you can also use `mitmproxy` (i.e. the TUI) or `mitmweb` this way instead.

### `ask` action

By default when you use the `ask` action, it will prompt you on the terminal.
Usually this is not ideal; both `mitmdump` *and* the command you are running are trying to access the terminal.

You can either [run mitmproxy in a separate terminal](#run-mitmproxy-separately) or use the `nsb_ask_cmd` option.

The `nsb_ask_cmd` allows you to specify a bash snippet that will get run instead of asking on the terminal.
The exit code determines whether the request is allowed (zero exit code) or blocked (non-zero exit code).
A short description of the network request is available in `$1`.
This could allow you to launch some kind of GUI confirmation dialog window.

For example, here is how to launch a zenity popup window:
```bash
nsb --set=nsb_ask_cmd='zenity --question --text="Trying to make request: $1" --ok-label=Allow --cancel-label=Block --title=nsb' ...
```

## Running without namespacing

If you can't or don't want to do namespacing for whatever reason, you can do a manual SOCKS set up.

Run in one terminal:
```bash
./nsb --only-mitmdump --mode=socks5@PORT ...
```

Then use something like 
[proxychains](https://github.com/rofl0r/proxychains-ng),
[gratfcp](https://github.com/hmgle/graftcp),
[socko](https://github.com/lincheney/socko),
or possibly others
to force your command through the mitm SOCKS proxy.
Note the limitations of each, including *scenarios where they do not work*.

## Notes and limitations

Smattering of other notes that you should pay attention to:

* `nsb` is susceptible to [DNS rebinding](https://en.wikipedia.org/wiki/DNS_rebinding).
    This can happen if you're DNS resolver is malicious or you have allowed resolution of a malicious domain.
    The workaround is not to allow resolution of unknown domains
    and/or block by destination IP with something like `block: ~dstip 10.0.0.0/8`
* filtering websocket connections with `~websocket` doesn't work right now, instead use something like `~http & ~hq "^upgrade: websocket\r$"`
* UDP, QUIC and possibly some TCP connections cannot be terminated normally.
    Instead, "blocking" them will just drop the network traffic and the client will probably eventually timeout.
* `nsb` sets `connection_strategy` to `lazy` by default.
    This is usually good because if the request ends up being blocked then no connection to the destination is ever made.
    However, this can break certain protocols where the server should send a message first, e.g. FTP.
    In this case, set it to eager: `nsb --set='connection_strategy=eager' ... `
* the command runs inside a separate network, mount, pid and user namespace.
    This may be a problem, e.g. `nsb ... -- sshfs ...` you will first run into a user issue which can be solved with something like
    `nsb -- unshare --mount --user --map-root-user sshfs ...`.
    However, the sshfs will then be mounted inside its mount namespace, not the "outside" one.
    You can "live with it" (you can get access into the namespace using `nsenter`)
    or consider if you are ok to [run it without namespacing](#running-without-namespacing).
* accessing the host loopback from inside `nsb`: use your LAN IP instead (e.g. your IP on your wifi).
    This will still be mitm-ed.
* accessing the servers running inside `nsb`: use the `--tcp-ports` or `--udp-ports` flag,
    e.g. `nsb --tcp-ports 127.0.0.1/8000 -- python -m http.server`,
    but do not *only* bind to `127.0.0.1` inside `nsb`, it won't work,
    see [the pasta docs](https://passt.top/builds/latest/web/passt.1.html#t) for more info.
* how to debug a request getting blocked:
    Crank up the logging (`nsb --set=termlog_verbosity=debug --set=flow_detail=4 ...`),
    and remember almost all requests do DNS first (so either allow all dns `allow:~dns` or specific domains `allow:~d domain.com`)
    or if you are accessing something directly by IP (e.g. on private subnet) then you need `nsb --set=nsb_allow_direct_ip=IP/MASK`
* if you need *very* customised behaviour, write your own mitmproxy addon and do `nsb --scripts=...`,
    since `nsb` is just running mitmdump and passes flags through,
    for example if instead of allowing/blocking you want to spoof or modify responses.
