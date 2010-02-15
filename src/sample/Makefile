# $Id$

All: ws_echo ws_chat

ws_echo : ws_echo.c
	gcc -o ws_echo -g ws_echo.c -levent

ws_chat : ws_chat.c
	gcc -o ws_chat -g ws_chat.c -levent

clean:
	rm -f *~ ws_echo ws_chat

# EOF
