%{

#define	YY_NO_INPUT

#if defined (DEBUG_LEX)
# include <stdio.h>
#endif

#include <string.h>

#include "mod_websocket_config.h"

#if ! defined (DEBUG_LEX)
# include "mod_websocket_config_parser.h"
#endif

int state, stack;
%}

%option nounput
%option yylineno

NUMBER                          [0-9]+
IDENT                           \"[^\"]*\"

SHARP_CHR			"#"
CR_CHR				"\n"
LF_CHR				"\r"
LP_CHR				"("
RP_CHR				")"
COMMA_CHR			","
EQ_CHR				"="

WEBSOCKET_SERVER_STR		"websocket.server"
WEBSOCKET_PING_INTERVAL_STR	"websocket.ping_interval"
WEBSOCKET_TIMEOUT_STR		"websocket.timeout"
WEBSOCKET_DEBUG_STR		"websocket.debug"

ASSIGN_STR			"=>"
HOST_STR			"\"host\""
PORT_STR			"\"port\""
PROTO_STR			"\"proto\""
BASE64_STR			"\"base64\""
ORIGINS_STR			"\"origins\""

%x STATE_COMMENT
%s STATE_SERVER STATE_QUOTE STATE_PING_INTERVAL STATE_TIMEOUT STATE_DEBUG
%%

<STATE_COMMENT>{CR_CHR}|{LF_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_COMMENT -> STATE(%d)\n", state);
#endif
    BEGIN state;
}
<STATE_COMMENT>. ;

<INITIAL>{SHARP_CHR} {
    state = INITIAL;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_SERVER_STR} {
    stack = 0;
    BEGIN STATE_SERVER;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER(%d): [%s]\n", STATE_SERVER, yytext);
#endif
#if ! defined (DEBUG_LEX)
    return WEBSOCKET_SERVER;
#endif
}
<STATE_SERVER>{SHARP_CHR} {
    state = STATE_SERVER;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}
{WEBSOCKET_PING_INTERVAL_STR} {
    BEGIN STATE_PING_INTERVAL;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_PING_INTERVAL(%d): [%s]\n", STATE_PING_INTERVAL, yytext);
#endif
#if ! defined (DEBUG_LEX)
    return WEBSOCKET_PING_INTERVAL;
#endif
}
<STATE_PING_INTERVAL>{SHARP_CHR} {
    state = STATE_PING_INTERVAL;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_TIMEOUT_STR} {
    BEGIN STATE_TIMEOUT;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_TIMEOUT(%d): [%s]\n", STATE_TIMEOUT, yytext);
#endif
#if ! defined (DEBUG_LEX)
    return WEBSOCKET_TIMEOUT;
#endif
}
<STATE_TIMEOUT>{SHARP_CHR} {
    state = STATE_TIMEOUT;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_DEBUG_STR} {
    BEGIN STATE_DEBUG;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_DEBUG(%d): [%s]\n", STATE_DEBUG, yytext);
#endif
#if ! defined (DEBUG_LEX)
    return WEBSOCKET_DEBUG;
#endif
}
<STATE_DEBUG>{SHARP_CHR} {
    state = STATE_DEBUG;
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

<STATE_SERVER>{LP_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
    stack++;
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_SERVER>{RP_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
    stack--;
    if (stack <= 0) {
        BEGIN INITIAL;
    }
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_SERVER>{COMMA_CHR}|{EQ_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_SERVER>{ASSIGN_STR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return ASSIGN;
#endif
}
<STATE_SERVER>{HOST_STR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return KEY_HOST;
#endif
}
<STATE_SERVER>{PORT_STR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return KEY_PORT;
#endif
}
<STATE_SERVER>{PROTO_STR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return KEY_PROTO;
#endif
}
<STATE_SERVER>{BASE64_STR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return KEY_BASE64;
#endif
}
<STATE_SERVER>{ORIGINS_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    return KEY_ORIGINS;
#endif
}
<STATE_SERVER>{NUMBER} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    yylval.value = strdup(yytext);
    return VALUE;
#endif
}
<STATE_SERVER>{IDENT} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX)
    yytext[yyleng - 1] = '\0';
    yylval.value = strdup(&yytext[1]);
    return VALUE;
#endif
}

<STATE_PING_INTERVAL>{EQ_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_PING_INTERVAL: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_PING_INTERVAL>{NUMBER} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_PING_INTERVAL: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX)
    yylval.value = strdup(yytext);
    return VALUE;
#endif
}

<STATE_TIMEOUT>{EQ_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_TIMEOUT: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_TIMEOUT>{NUMBER} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_TIMEOUT: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX)
    yylval.value = strdup(yytext);
    return VALUE;
#endif
}

<STATE_DEBUG>{EQ_CHR} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_DEBUG: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX)
    return yytext[0];
#endif
}
<STATE_DEBUG>{NUMBER} {
#if defined (DEBUG_LEX)
    fprintf(stderr, "STATE_DEBUG: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX)
    yylval.value = strdup(yytext);
    return VALUE;
#endif
}

{CR_CHR}|{LF_CHR}|. ;

%%
