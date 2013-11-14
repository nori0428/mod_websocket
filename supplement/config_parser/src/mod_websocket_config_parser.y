%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <netdb.h>

#include "mod_websocket_config.h"

static mod_websocket_config_t *websocket_config;

extern int yylex();
extern int yylineno;
extern FILE *yyin;

void yyerror(const char *e) {
    fprintf(stderr, "Error: %s occurred at near line.%d\n", e, yylineno);
}

int yywrap() {
    return 1;
}

%}

%code requires {
    typedef enum {
        MOD_WEBSOCKET_CONFIG_KEY_HOST,
        MOD_WEBSOCKET_CONFIG_KEY_PORT,
        MOD_WEBSOCKET_CONFIG_KEY_PROTO,
        MOD_WEBSOCKET_CONFIG_KEY_BASE64,
        MOD_WEBSOCKET_CONFIG_KEY_ORIGINS,
    } mod_websocket_key_t;

    typedef struct {
        mod_websocket_key_t key;
        void *val;
    } mod_websocket_keyvalue_t;
}

%union {
    char *value;
    mod_websocket_keyvalue_t keyvalue;
    mod_websocket_origin_t *origin;
    mod_websocket_backend_t *backend;
    mod_websocket_resource_t *resource;
}

%token WEBSOCKET_SERVER
%token KEY_HOST KEY_PORT KEY_PROTO KEY_BASE64 KEY_ORIGINS
%token VALUE
%token ASSIGN
%token WEBSOCKET_PING_INTERVAL
%token WEBSOCKET_TIMEOUT
%token WEBSOCKET_DEBUG

%type <value> VALUE
%type <keyvalue> keyvalue
%type <origin> origin
%type <backend> backend
%type <resource> resource resource_list
%start definitions

%%

definitions:
                definition
        |       definitions definition
                ;

definition:
                server_config
        |       ping_interval_config
        |       timeout_config
        |       debug_config
                ;

server_config:
                WEBSOCKET_SERVER '=' '(' resource_list ')'
                {
                    websocket_config->resources = $4;
                }
                ;

resource_list:
                resource
                {
                    $$ = $1;
                }
        |       resource_list ',' resource
                {
                    $$ = $3;
                    $$->next = $1;
                }
                ;

resource:
                VALUE ASSIGN '(' backend ')'
                {
                    $$ = (mod_websocket_resource_t *)malloc(sizeof(mod_websocket_resource_t));
                    $$->key = $1;
                    $$->backend = $4;
                    $$->next = NULL;
                }
                ;

backend:
                keyvalue
                {
                    struct servent *serv;

                    $$ = (mod_websocket_backend_t *)malloc(sizeof(mod_websocket_backend_t));
                    $$->host = NULL;
                    $$->port = -1;
                    $$->proto = MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP;
                    $$->base64 = 0;
                    $$->origins = NULL;
                    switch ($1.key) {
                    case MOD_WEBSOCKET_CONFIG_KEY_HOST:
                        $$->host = (char *)$1.val;
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_PORT:
                        $$->port = (int)strtol((char *)$1.val, NULL, 10);
                        if ($$->port == 0) {
                            serv = getservbyname((char *)$1.val, NULL);
                            if (serv == NULL) {
                                $$->port = -1;
                            } else {
                                $$->port = htons(serv->s_port);
                            }
                        }
                        free($1.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_PROTO:
                        if (strncasecmp((char *)$1.val, "websocket", strlen("websocket")) == 0) {
                            $$->proto = MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET;
                        } else {
                            $$->proto = MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP;
                        }
                        free($1.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_BASE64:
                        if (strncasecmp((char *)$1.val, "true", strlen("true")) == 0 ||
                            strncmp((char *)$1.val, "1", strlen("1")) == 0) {
                            $$->base64 = 1;
                        } else {
                            $$->base64 = 0;
                        }
                        free($1.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_ORIGINS:
                        $$->origins = (mod_websocket_origin_t *)$1.val;
                        break;
                    default:
                        break;
                    }
                }
        |       backend ',' keyvalue
                {
                    struct servent *serv;

                    $$ = $1;
                    switch ($3.key) {
                    case MOD_WEBSOCKET_CONFIG_KEY_HOST:
                        $$->host = (char *)$3.val;
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_PORT:
                        $$->port = (int)strtol((char *)$3.val, NULL, 10);
                        if ($$->port == 0) {
                            serv = getservbyname((char *)$3.val, NULL);
                            if (serv == NULL) {
                                $$->port = -1;
                            } else {
                                $$->port = htons(serv->s_port);
                            }
                        }
                        free($3.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_PROTO:
                        if (strncasecmp((char *)$3.val, "websocket", strlen("websocket")) == 0) {
                            $$->proto = MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET;
                        } else {
                            $$->proto = MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP;
                        }
                        free($3.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_BASE64:
                        if (strncasecmp((char *)$3.val, "true", strlen("true")) == 0 ||
                            strncmp((char *)$3.val, "1", strlen("1")) == 0) {
                            $$->base64 = 1;
                        } else {
                            $$->base64 = 0;
                        }
                        free($3.val);
                        break;
                    case MOD_WEBSOCKET_CONFIG_KEY_ORIGINS:
                        $$->origins = (mod_websocket_origin_t *)$3.val;
                        break;
                    default:
                        break;
                    }
                }
                ;

keyvalue:
                KEY_HOST ASSIGN VALUE
                {
                    $$.key = MOD_WEBSOCKET_CONFIG_KEY_HOST;
                    $$.val = (void *)$3;
                }
        |       KEY_PORT ASSIGN VALUE
                {
                    $$.key = MOD_WEBSOCKET_CONFIG_KEY_PORT;
                    $$.val = (void *)$3;
                }
        |       KEY_PROTO ASSIGN VALUE
                {
                    $$.key = MOD_WEBSOCKET_CONFIG_KEY_PROTO;
                    $$.val = (void *)$3;
                }
        |       KEY_BASE64 ASSIGN VALUE
                {
                    $$.key = MOD_WEBSOCKET_CONFIG_KEY_BASE64;
                    $$.val = (void *)$3;
                }
        |       KEY_ORIGINS ASSIGN '(' origin ')'
                {
                    $$.key = MOD_WEBSOCKET_CONFIG_KEY_ORIGINS;
                    $$.val = (void *)$4;
                }
                ;

origin:
                VALUE
                {
                    $$ = (mod_websocket_origin_t *)malloc(sizeof(mod_websocket_origin_t));
                    $$->origin = $1;
                    $$->next = NULL;
                }
        |       origin ',' VALUE
                {
                    $$ = (mod_websocket_origin_t *)malloc(sizeof(mod_websocket_origin_t));
                    $$->origin = $3;
                    $$->next = $1;
                }
                ;

ping_interval_config:
                WEBSOCKET_PING_INTERVAL '=' VALUE
                {
                    websocket_config->ping_interval = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

timeout_config:
                WEBSOCKET_TIMEOUT '=' VALUE
                {
                    websocket_config->timeout = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

debug_config:
                WEBSOCKET_DEBUG '=' VALUE
                {
                    websocket_config->debug = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

%%

mod_websocket_config_t *mod_websocket_config_parse(const char* fname) {
    FILE *fp = NULL;

    if ((fp = fopen(fname, "r"))  == NULL) {
        fprintf(stderr, "file is not found: %s\n", fname);
        return NULL;
    }
    if (flock(fileno(fp), LOCK_SH) < 0) {
        fprintf(stderr, "file is locked: %s\n", fname);
        fclose(fp);
        return NULL;
    }
    websocket_config = (mod_websocket_config_t *)malloc(sizeof(mod_websocket_config_t));
    if (websocket_config == NULL) {
        fprintf(stderr, "no memory\n");
        fclose(fp);
        return NULL;
    }
    websocket_config->resources = NULL;
    websocket_config->ping_interval = 0;
    websocket_config->timeout = 30;
    websocket_config->debug = 0;
    yyin = fp;
    if (yyparse()) {
        mod_websocket_config_free(websocket_config);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    return websocket_config;
}

void mod_websocket_config_free(mod_websocket_config_t *config) {
    mod_websocket_origin_t *origin, *origin_next;
    mod_websocket_backend_t *backend;
    mod_websocket_resource_t *resource, *resource_next;

    if (config == NULL) {
        return;
    }
    resource = config->resources;
    while (resource) {
        if (resource->key != NULL) {
            free(resource->key);
        }
        backend = resource->backend;
        if (backend) {
            if (backend->host != NULL) {
                free(backend->host);
            }
            origin = backend->origins;
            while (origin) {
                if (origin->origin) {
                    free(origin->origin);
                }
                origin_next = origin->next;
                free(origin);
                origin = origin_next;
            }
            free(backend);
        }
        resource_next = resource->next;
        free(resource);
        resource = resource_next;
    }
    free(config);
    return;
}

void mod_websocket_config_print(mod_websocket_config_t *config) {
    mod_websocket_origin_t *origin;
    mod_websocket_backend_t *backend;
    mod_websocket_resource_t *resource = NULL;

    if (config == NULL) {
        return;
    }
    fprintf(stdout, "websocket.server = (\n");
    for (resource = config->resources; resource; resource = resource->next) {
        fprintf(stdout, "\t\"%s\" =>\n", resource->key);
        backend = resource->backend;
        fprintf(stdout, "\t(\n\t\thost = \"%s\"\n\t\tport = %d\n",
                backend->host, backend->port);
        switch(backend->proto) {
        case MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET:
            fprintf(stdout, "\t\tproto = MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET\n");
            break;
        case MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP:
        default:
            fprintf(stdout, "\t\tproto = MOD_WEBSOCKET_BACKEND_PROTOCOL_TCP\n");
            break;
        }
        if (backend->base64) {
            fprintf(stdout, "\t\tbase64 = true");
            if (backend->proto == MOD_WEBSOCKET_BACKEND_PROTOCOL_WEBSOCKET) {
                fprintf(stdout, " // However, this does not have a meaning.\n");
            } else {
                fprintf(stdout, "\n");
            }
        }
        if (backend->origins != NULL) {
            fprintf(stdout, "\t\tallowed_origins = ( ");
            for (origin = backend->origins; origin; origin = origin->next) {
                fprintf(stdout, "\"%s\"", origin->origin);
                if (origin->next != NULL) {
                    fprintf(stdout, ", ");
                }
            }
            fprintf(stdout, " )\n");
        }
        fprintf(stdout, "\t)\n");
    }
    fprintf(stdout, ")\n");
    fprintf(stdout, "websocket.ping_interval = %d\n", config->ping_interval);
    fprintf(stdout, "websocket.timeout = %d\n", config->timeout);
    fprintf(stdout, "websocket.debug = %d\n", config->debug);
    return;
}
