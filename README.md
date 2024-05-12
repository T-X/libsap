# libsap / SAP tool

*An SAP library and tool for RFC2974 ("Session Announcement Protocol")*

This tool and library allows to announce multicasted multimedia sessions via
SAP/[RFC2974](https://datatracker.ietf.org/doc/html/rfc2974).

## Build

Requires: autoconf, libtool

(Debian: `$ apt-get install autoconf libtool`)

```
$ git clone https://github.com/T-X/libsap.git
$ cd libsap
$ autoreconf -i && ./configure && make
```

## Usage: sap tool

```
$ sap -h
Usage: sap [<options> ...]

Options:
    -4                                  IPv4-only mode
    -6                                  IPv6-only mode
    -d <address|hostname>               Payload's destination (default: from c= in SDP payload)
    -p <file|fifo|->                    Payload file (default: -)
    -b <bw-limit>                       Total bits/s for all sessions in an SAP group (default: 4000)
    -C                                  Disable compression
    -h                                  This help page

Debug options: (typ. not RFC compliant)
    -D                                  Disable payload destination from SDP detection
    -S <address|hostname>               SAP destination (default: from payload destinations only)
    -t <type>                           Payload type (default: "application/sdp")
    -T <announce|terminate>             Message type, sets debug mode (default: standard/daemon mode)
    -I <msg-id-hash>                    Message ID hash (default: random)
    -i <interval>                       Interval override in seconds (default: 300)
    -J                                  Disable interval jitter
    -c <count>                          Number of messages to send
```

Standard options:

**-d <address|hostname>:**

Specify the payload's destination, the multicast destination of your media
stream that is. The sap tool will figure out the according SAP group address(es)
for it for you. This can be an IPv4/IPv6 multicast address or a hostname
(which resolves to an IPv4/IPv6 multicast address).

If unspecified then the payload destination(s) will be parsed from the
"c=" option(s) in the provided SDP payload.

This option can be specified multiple times.

**-p <file|fifo|->:**

A file or named pipe which provides the (typically SDP) payload we will
announce via SAP.

Reads from "-" (standard in) by default.

For SDP content the "c=" option(s) in it will also be used to figure out the
SAP group(s).

**-b <bw-limit>:**

The overall bits/s limit for all SAP announcements on a specific SAP group.
The sap tool will increase its interval if this limit gets hit.

Note: We don't measure the real, overall SAP throughput. Instead we estimate
it from the number of detected SAP sessions/announcers and their SAP payload
sizes. And we assume that they use the same bandwidth limit and interval
settings as we do.

Defaults to 4000 (bits/s).

**-C:**

Disable the SAP zlib compression feature, transfer the payload and
payload type uncompressed, in plaintext.

Debug options:

**-t <type>:**

The payload type. Defaults to: "application/sdp"

**-T <announce|terminate>:**

By default we send SAP announcements and will send SAP termination
messages when exiting. Setting this option allows to send/set a
specific SAP message type only.

When this is set then we assume that sap tool is used as a debug utility
and that the user expects a more ping utility like behaviour. Which has
the following three implications:

1) No extra SAP terminate will be send on exit.
2) If a "-c" count option is given will exit immediately after reaching
that count.
3) The first SAP packet(s) is/are send immidiately and not after a first
interval period elapsed.

**-I <msg-id-hash>:**

Set the 16 bit SAP message ID hash. By default this is a random one.
Format is either an integer between 0 and 65535. Or a hexadecimal
number between 0x0000 and 0xffff (or 0xFFFF).

You might want to use it when using the "-T terminate" option to
terminate a specific SAP session.

**-i <interval>:**

Set the (minimum) SAP interval in seconds. Defaults to 300, as required
by RFC2974. Changing it is not quite RFC compliant.

Note that the actual interval can be higher due to hitting the
SAP group bandwidth limit (also see the "-b" option).

Also some jitter is applied to the interval by default, as required
by the RFC.

**-J:**

Disable jitter on the SAP interval, to have a more strict SAP interval.
Note that jitter is useful to reduce the risk for packet
bursts / congestion / collisions.

**-c <count>:**

Number of SAP packets (per SAP group) to send before exiting
(excluding the potential extra SAP terminate on exit).
Defaults to 0 = inifinite / no limit.


### sap tool example usage

The easiest and RFC compliant way to use:

```
$ cat ./my-media-session.sdp
v=0
o=jdoe 2890844526 2890842807 IN IP6 2001:67c:2d50:0:be24:11ff:fe5e:d24f
s=FREIRAUMDISKO
i=A community managed Radio stream (via MPD), tracks from Jamendo.com
e=tux@c0d3.blue (T_X)
c=IN IP6 ff7e:240:2001:67c:2d50:0:545f:5800
t=0 0
a=recvonly
m=audio 5000 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=fmtp:96 stereo=1; sprop-stereo=1
$
$ cat ./my-multimedia-session.sdp | sap
```

However note that this way announcements will be send every 5mins only.
For a more responsive (but not quite RFC compliant?) way, you can
reduce the interval as follows, via "-i":

```
$ cat ./my-multimedia-session.sdp | sap -i 5
```

VLC uses 5 seconds for instance. So that a client will need to wait for
5 seconds maximum to detect a session. Note that we will still increase the
interval again if the overall SAP group bandwidth limit (default: 4000 bits/s,
configurable via "-b") is reached. Assuming an average of 500 bytes per
SAP/SDP message, the 5 seconds interval would be reached with 5 SAP announcers
on the same SAP group, for example.

### Signals

If the sap tool receives a SIGINT, SIGHUP or SIGTERM then it will shut down
in an orderly fashion and will send an SAP terminate message for each of its
announced SAP sessions before exiting.

If "-T" was given for an explicit message type then we won't send the
SAP terminate messages as we assume that the sap tool is used in a full control
"debug mode".

## Usage: libsap

```C
struct sap_ctx *sap_init_custom(char *payload_dests[],
                                int payload_dest_af,
                                char *payload_filename,
                                char *payload_type,
                                int msg_type,
                                uint16_t *msg_id_hash,
                                unsigned int interval,
                                int no_jitter,
                                unsigned long count,
                                long bw_limit);
struct sap_ctx *sap_init_fast(char *payload_filename);
struct sap_ctx *sap_init(char *payload_filename);

int sap_run(struct sap_ctx *ctx);
int sap_start(struct sap_ctx *ctx);
void sap_stop(struct sap_ctx *ctx);
void sap_term(struct sap_ctx *ctx);

void sap_free(struct sap_ctx *ctx);
```

### libsap example, single-threaded, blocking

```C
#include <libsap.h>

int main(int argc, char *argv[])
{
    struct sap_ctx *ctx;

    /* initialize SAP context with our settings */
    ctx = sap_init("/tmp/my-multimedia-session.sdp");
    if (!ctx)
        return 1;

    /* start SAP operation, blocks, can be interrupted by sap_term() */
    sap_run(ctx);

    /* cleanup allocated SAP context */
    sap_free(ctx);

    return 0;
}
```

### libsap example, multi-threaded, non-blocking

```C
#include <unistd.h>
#include <libsap.h>

static void my_important_work(void)
{
    sleep(15);
}

int main(int argc, char *argv[])
{
    struct sap_ctx *ctx;
    int ret = 2;

    /* initialize SAP context with our settings;
     * sap_init_fast() uses a (not quite RFC conformant,
     * but more responsive) 5 instead of 300 seconds
     * interval
     */
    ctx = sap_init_fast("/tmp/my-multimedia-session.sdp");
    if (!ctx)
        return 1;

    /* start SAP operation in a separate thread */
    if (sap_start(ctx) < 0)
        goto out;

    /* do your stuff here, SAP runs in the background */
    my_important_work();

    /* stop SAP operation/thread, blocks briefly */
    sap_stop(ctx);
    ret = 0;
out:
    /* cleanup allocated SAP context */
    sap_free(ctx);
    return ret;
}
```

## TODOs

* If "-p" is a pipe, keep it  open and update session if new SDP is received
  (use "\r\n\r\n" and/or "\0" as delimeters?)
* compression / zlib support
* authentication
* encryption
* shrink SAP terminate message size
* replace / add alternatives for Linux-isms? make multi-platform compatible
* add an MTU / packet size limit option, defaulting to 1000 bytes per RFC
  (we can't use/enforce IP fragmentation for UDP/multicast packets or can we?)
* add a "-D" option for an explicit SAP group multicast address
  (VLC has such an option)
* add a "-O" option to set an explicit/alternative SAP orig-source address
* some more verbose output for sap tool?
* add getopt\_long() / long option names to sap tool
* add SIGUSR1 for status output to stdout to sap tool?
* add a `payload_fd` option as an alternative to `payload_filename` to
  `sap_init_custom()`?
* add a `sap_run_noblock()` variant, together with an `sap_pollfd()`
  which can be checked for work/updates on our internal epoll fd?
  and which can be called again / continued?
* add a `sap_run_wait(ctx, timeout_msec)` variant which returns after
  timeout\_msec milliseconds, and which can be called again / continued?
* implement SAP client side:
 * sap tool:
   * add a "-l"/listener option, which avoids SAP transmissions, but joins
     all SAP groups
   * output newly added/detected/terminated SAP sessions to stdout or file/pipe
     if "-p" is given (don't output redundant "keep-alive" SAP announcements
     or unknown SAP terminations)
 * libsap:
   * add listener function(s) to the libsap library, text stream based
     through `sap_init()`'s `payload_filename` option, but maybe also
     s.th. more accessible, with an already parsed format, like a
     `int sap_listener(int (*callback)(struct sap_event))`, with
     `struct sap_event { .msg_type, .msg, ... }`
* MZAP (RFC2776) support
* an SAP caching proxy implementation? To have faster intervals downstream
  and slower ones upstream (both for layer 2/bridged + layer 3/routed setups)
* A nice readthedocs and/or doxygen pages for better documentation?

## Honorable mentions

Kudos to the VLC project, which has a nice, usable, minimal SAP implementation.
This preceding work helped a lot to figure out some of the SAP RFC details
and helped to test and verify this implementation.

* https://code.videolan.org/videolan/vlc/-/blob/master/modules/services_discovery/sap.c
* https://code.videolan.org/videolan/vlc/-/blob/master/src/stream_output/sap.c
* https://code.videolan.org/videolan/minisapserver
