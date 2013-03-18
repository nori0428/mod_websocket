%{

#define	YY_NO_INPUT

//#define	DEBUG
//#define	DEBUG_LEX_ONLY

#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
# include <stdio.h>
#endif

#include "mod_websocket_config.h"

#if ! defined (DEBUG_LEX_ONLY)
# include "parser.h"
#endif

int state, stack;
%}

%option nounput

NUMBER				[0-9]+
IDENT				[a-zA-Z0-9.:/_-]+

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
TYPE_STR			"\"type\""
SUBPROTO_STR			"\"subproto\""
ORIGINS_STR			"\"origins\""
LOCALE_STR			"\"locale\""

%x STATE_COMMENT
%s STATE_SERVER STATE_PING_INTERVAL STATE_TIMEOUT STATE_DEBUG
%%

<STATE_COMMENT>{CR_CHR}|{LF_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_COMMENT -> STATE(%d)\n", state);
#endif
    BEGIN state;
}
<STATE_COMMENT>. ;

<INITIAL>{SHARP_CHR} {
    state = INITIAL;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_SERVER_STR} {
    stack = 0;
    BEGIN STATE_SERVER;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER(%d): [%s]\n", STATE_SERVER, yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return SERVER_CONFIG;
#endif
}
<STATE_SERVER>{SHARP_CHR} {
    state = STATE_SERVER;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_PING_INTERVAL_STR} {
    BEGIN STATE_PING_INTERVAL;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_PING_INTERVAL(%d): [%s]\n", STATE_PING_INTERVAL, yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return PING_INTERVAL_CONFIG;
#endif
}
<STATE_PING_INTERVAL>{SHARP_CHR} {
    state = STATE_PING_INTERVAL;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_TIMEOUT_STR} {
    BEGIN STATE_TIMEOUT;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_TIMEOUT(%d): [%s]\n", STATE_TIMEOUT, yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return TIMEOUT_CONFIG;
#endif
}
<STATE_TIMEOUT>{SHARP_CHR} {
    state = STATE_TIMEOUT;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

{WEBSOCKET_DEBUG_STR} {
    BEGIN STATE_DEBUG;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_DEBUG(%d): [%s]\n", STATE_DEBUG, yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return DEBUG_CONFIG;
#endif
}
<STATE_DEBUG>{SHARP_CHR} {
    state = STATE_DEBUG;
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE(%d) -> STATE_COMMENT\n", state);
#endif
    BEGIN STATE_COMMENT;
}

<STATE_SERVER>{LP_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
    stack++;
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_SERVER>{RP_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
    stack--;
    if (stack <= 0) {
        BEGIN INITIAL;
    }
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_SERVER>{COMMA_CHR}|{EQ_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_SERVER>{ASSIGN_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return ASSIGN;
#endif
}
<STATE_SERVER>{HOST_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = HOST;
    return KEY;
#endif
}
<STATE_SERVER>{PORT_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = PORT;
    return KEY;
#endif
}
<STATE_SERVER>{TYPE_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = TYPE;
    return KEY;
#endif
}
<STATE_SERVER>{SUBPROTO_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = SUBPROTO;
    return KEY;
#endif
}
<STATE_SERVER>{LOCALE_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = LOCALE;
    return KEY;
#endif
}
<STATE_SERVER>{ORIGINS_STR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    yylval.assign.key = ORIGINS;
    return KEY;
#endif
}
<STATE_SERVER>{NUMBER}|{IDENT} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_SERVER: [%s]\n", yytext);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    size_t len = strlen(yytext);

    yylval.value = (char*)malloc(len + 1);
    memcpy(yylval.value, yytext, len);
    yylval.value[len] = '\0';
    return VALUE;
#endif
}

<STATE_PING_INTERVAL>{EQ_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_PING_INTERVAL: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_PING_INTERVAL>{NUMBER} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_PING_INTERVAL: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX_ONLY)
    size_t len = strlen(yytext);

    yylval.value = malloc(len + 1);
    memcpy(yylval.value, yytext, len);
    yylval.value[len] = '\0';
    return VALUE;
#endif
}

<STATE_TIMEOUT>{EQ_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_TIMEOUT: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_TIMEOUT>{NUMBER} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_TIMEOUT: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX_ONLY)
    size_t len = strlen(yytext);

    yylval.value = malloc(len + 1);
    memcpy(yylval.value, yytext, len);
    yylval.value[len] = '\0';
    return VALUE;
#endif
}

<STATE_DEBUG>{EQ_CHR} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_DEBUG: [%c]\n", yytext[0]);
#endif
#if ! defined (DEBUG_LEX_ONLY)
    return yytext[0];
#endif
}
<STATE_DEBUG>{NUMBER} {
#if defined (DEBUG) || defined (DEBUG_LEX_ONLY)
    fprintf(stderr, "STATE_DEBUG: [%s]\n", yytext);
#endif
    BEGIN INITIAL;
#if ! defined (DEBUG_LEX_ONLY)
    size_t len = strlen(yytext);

    yylval.value = malloc(len + 1);
    memcpy(yylval.value, yytext, len);
    yylval.value[len] = '\0';
    return VALUE;
#endif
}

{CR_CHR}|{LF_CHR}|. ;

%%

#if defined (DEBUG_LEX_ONLY)
int
main(int argc, char **argv) {
    FILE *input_file = stdin;

    if (argc > 1 && (input_file = fopen(*++argv, "r")) == NULL) {
        fprintf(stderr, "Can't open %s.\n", *argv);
        return -1;
    }
    yyin = input_file;
    BEGIN(INITIAL);
    yylex();
}
#endif
