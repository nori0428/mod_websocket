/**
 * $Id$
 */

function mua() {
    var ws, obj, strbuf = "";

    function showMsg(msg) {
        var txt;

        switch (parseInt(msg.split(' ')[0], 10)) {
        case 221:
	    break;
        case 354:
            txt = $('<div></div>');
            $('#terminal').append(txt);
            obj = txt;
            break;
        default:
            txt = $('<div>smtp> <span id="caret">|</span></div>');
            $('#terminal').append(txt);
            obj = txt;
            break;
        }
    }
    function bshdl(e) {
        if (e.which == 8 && strbuf.length > 0) { // backspace
            e.preventDefault();
            obj.text(obj.text().substr(0, obj.text().length - 2));
            obj.html(obj.text() + '<span id="caret">|</span>');
            strbuf = strbuf.substr(0, strbuf.length - 1);
            console.log('string: ' + strbuf);
        } else if (e.which == 8) {
            e.preventDefault();
        }
    }
    function keyhdl(e) {
        var c;
        var txt;

        e.preventDefault();
        e.stopPropagation();
        if (65 <= e.which && e.which <= 90) { // alphabet
            if (!e.shiftKey) {
                e.which += 32;
            }
        } else if (e.which == 13) { // return
            strbuf += '\n';
            ws.send(strbuf);
            strbuf = "";
            obj.text(obj.text().substr(0, obj.text().length - 1));
            txt = $('<div></div>');
            $('#terminal').append(txt);
            obj = txt;
            return;
        } else if (e.which == 8) { // bs
            return;
        }
        c = String.fromCharCode(e.which);
        strbuf += c;
        console.log('string: ' + strbuf);
        obj.text(obj.text().substr(0, obj.text().length - 1) + c);
        obj.html(obj.text() + '<span id="caret">|</span>');
    }
    $(window).keypress(keyhdl);
    $(window).keydown(bshdl);

    ws = new WebSocket('ws://' + location.host + '/smtp');
    ws.onopen = function() {
        var txt = $('<div>opened websocket and connected to SMTPd</div>');
        $('#terminal').append(txt);
    };
    ws.onmessage = function(e) {
        var txt = document.createTextNode(e.data.trim());
        $('#terminal').append(txt);
        $('#terminal').append('<br>');
        showMsg(e.data);
    };
    ws.onclose = function() {
        var txt = $('<div>closed websocket</div>');
        $('#terminal').append(txt);
    };
}

/* EOF */
