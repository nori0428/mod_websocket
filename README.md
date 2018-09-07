mod_websocket [![Build Status](https://travis-ci.org/nori0428/mod_websocket.png?branch=master)](https://travis-ci.org/nori0428/mod_websocket)
=============

Notice
-------

DEAD.  
use lighttpd v1.4.46 or after w/ mod_proxy and mod_wstunnnel.  

Great thanks to lighty developpers.

What is this?
-------

mod_websocket.c provides a WebSocket extension for lighttpd HTTP server ver 1.4.28-1.4.33(http://www.lighttpd.net/)

How does mod_websocket work?
------

1. WebSocket Proxy.  
  Only Transfer WebSocket handshake and frame.
  But ssl is terminated by mod_websocket.  
  client <--- ssl ---> lighttpd - mod_websocket <--- tcp ---> your websocket server

2. WebSocket-TCP Proxy.  
  Please see these figures.  
  [![abst](https://lh3.googleusercontent.com/-mybZ2qfyAek/S4JcS6DpUtI/AAAAAAAAAFk/6JjcPLk_6PE/s144/demo_sequence.jpg)](https://picasaweb.google.com/lh/photo/KnX-73pr7ApCabc9NqBqNQ?feat=directlink)[![detail](https://lh5.googleusercontent.com/-C56_ous2TEI/S4JTaajRaRI/AAAAAAAAAFc/n5o5oYfYjMU/s144/websocket-mod_websocket-flow.jpg)](https://picasaweb.google.com/lh/photo/fb97lbN-O1Q5VkfJXyqN2w?feat=directlink)

How can I use this?
------

First, clone code.

<code>
    $ git clone --recursive git://github.com/nori0428/mod_websocket.git
</code>

and follow the instructions in [INSTALL](https://github.com/nori0428/mod_websocket/blob/master/INSTALL) or read [Wiki Page](https://github.com/nori0428/mod_websocket/wiki/_pages) for Quick Start.

Characteristics
------

1. Supports WebSocket Proxy and WebSocket-TCP Proxy.  
  You can choose either WebSocket Proxy or WebSocket-TCP Proxy to every request URI.

2. Supported protocols: hybi-00 and RFC-6455.  
  See [Can I use...](http://caniuse.com/#feat=websockets) for browser support.

3. Automatic base64 {en, de}code on hybi-00 spec by setting "type" section "binary".  
  (my answer of https://github.com/nori0428/mod_websocket/issues/19)  
  A more detailed description has been described in the [INSTALL](https://github.com/nori0428/mod_websocket/blob/master/INSTALL) and [websocket.conf.sample](https://github.com/nori0428/mod_websocket/blob/master/sample/etc/conf.d/websocket.conf.sample).

LICENCE
------

see  [COPYING](https://github.com/nori0428/mod_websocket/blob/master/COPYING).(same as lighty's LICENCE) and see lighttpd LICENCE.

great thanks to
------

Taiyo Fujii(@t_trace), Kensaku Komatsu(@komasshu), Toshiro Takahashi(@tohirot), Nobuyoshi Miyokawa(@nmiyo), Takezo(@velvetpass), Aaron Mitchell, Bejhan Jetha, Andrea D'Amore, Doug Johnson
and lighty developpers!
