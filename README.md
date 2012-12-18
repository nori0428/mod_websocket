mod_websocket [![Build Status](https://travis-ci.org/nori0428/mod_websocket.png?branch=master)](https://travis-ci.org/nori0428/mod_websocket)
=============

What is this?
-------

mod_websocket.c provides a WebSocket extension for lighttpd HTTP server ver 1.4.28 - 1.4.32(http://www.lighttpd.net/)

How does mod_websocket work?
------

Please see these figures.

[![abst](https://lh3.googleusercontent.com/-mybZ2qfyAek/S4JcS6DpUtI/AAAAAAAAAFk/6JjcPLk_6PE/s144/demo_sequence.jpg)](https://picasaweb.google.com/lh/photo/KnX-73pr7ApCabc9NqBqNQ?feat=directlink)[![detail](https://lh5.googleusercontent.com/-C56_ous2TEI/S4JTaajRaRI/AAAAAAAAAFc/n5o5oYfYjMU/s144/websocket-mod_websocket-flow.jpg)](https://picasaweb.google.com/lh/photo/fb97lbN-O1Q5VkfJXyqN2w?feat=directlink)

How can I use this?
------

First, clone code.

<code>
    $ git clone git://github.com/nori0428/mod_websocket.git
</code>

and follow the instructions in [INSTALL](https://github.com/nori0428/mod_websocket/blob/master/INSTALL) or read [Wiki Page](https://github.com/nori0428/mod_websocket/wiki/_pages) for Quick Start.

Characteristics
------

1. Supported protocols: hybi-00 and RFC-6455.
   see [Can I use...](http://caniuse.com/#feat=websockets) for  browser suppot.

2. Automatic base64 {en, de}code on hybi-00 spec by specifying "bin" type in websocket.conf.

  (my answer of https://github.com/nori0428/mod_websocket/issues/19)

  A more detailed description has been described in the [INSTALL](https://github.com/nori0428/mod_websocket/blob/master/INSTALL).

LICENCE
------

see  [COPYING](https://github.com/nori0428/mod_websocket/blob/master/COPYING).(same as lighty's LICENCE) and see lighttpd LICENCE.

great thanks to
------

Taiyo Fujii(@t_trace), Kensaku Komatsu(@komasshu), Toshiro Takahashi(@tohirot), Nobuyoshi Miyokawa(@nmiyo), Takezo(@velvetpass), Aaron Mitchell, Bejhan Jetha,
and lighty developpers!
