%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <netdb.h>

#include "mod_websocket_config.h"

static mod_websocket_config_t *websocket_config;

extern int yylex();
extern FILE *yyin;

void yyerror(const char *e) {
    fprintf(stderr, "%s\n", e);
}

int yywrap() {
    return 1;
}

%}

%union {
    char *value;
    mod_websocket_assign_t assign;
    mod_websocket_origin_t *origin;
    mod_websocket_backend_t *backend;
    mod_websocket_resource_t *resource;
}

%token SERVER_CONFIG PING_INTERVAL_CONFIG TIMEOUT_CONFIG DEBUG_CONFIG KEY VALUE ASSIGN
%type <value> VALUE
%type <assign.key> KEY
%type <assign> assignment
%type <origin> origin
%type <backend> backend backend_list
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
                SERVER_CONFIG '=' '(' resource_list ')'
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
                    $$->backends = $4;
                    $$->next = NULL;
                }
        |       VALUE ASSIGN '(' backend_list ')'
                {
                    $$ = (mod_websocket_resource_t *)malloc(sizeof(mod_websocket_resource_t));
                    $$->key = $1;
                    $$->backends = $4;
                    $$->next = NULL;
                }
                ;

backend_list:
                '(' backend ')'
                {
                    $$ = $2;
                }
        |       backend_list ',' '(' backend ')'
                {
                    $$ = $4;
                    $$->next = $1;
                }
                ;

backend:
                assignment
                {
                    struct servent *serv;

                    $$ = (mod_websocket_backend_t *)malloc(sizeof(mod_websocket_backend_t));
                    $$->host = NULL;
                    $$->subproto = NULL;
                    $$->locale = NULL;
                    $$->origins = NULL;
                    $$->proto = NULL;
                    switch ($1.key) {
                    case HOST:
                        $$->host = (char *)$1.val;
                        break;
                    case PORT:
                        $$->port = (int)strtol((char *)$1.val, NULL, 10);
                        if ($$->port == 0) {
                            serv = getservbyname((char *)$1.val, NULL);
                            if (serv == NULL) {
                                $$->port = -1;
                            } else {
                                $$->port = htons(serv->s_port);
                            }
                        }
                        free((char *)$1.val);
                        break;
                    case TYPE:
                        $$->type = (strncasecmp((char *)$1.val, "bin", strlen("bin")) == 0);
                        free((char *)$1.val);
                        break;
                    case SUBPROTO:
                        $$->subproto = (char *)$1.val;
                        break;
                    case LOCALE:
                        $$->locale = (char *)$1.val;
                        break;
                    case ORIGINS:
                        $$->origins = (mod_websocket_origin_t *)$1.val;
                        break;
                    case PROTO:
                        $$->proto = (char *)$1.val;
                        break;
                    default:
                        break;
                    }
                    $$->next = NULL;
                }
        |       backend ',' assignment
                {
                    struct servent *serv;

                    $$ = $1;
                    switch ($3.key) {
                    case HOST:
                        $$->host = (char *)$3.val;
                        break;
                    case PORT:
                        $$->port = (int)strtol((char *)$3.val, NULL, 10);
                        if ($$->port == 0) {
                            serv = getservbyname((char *)$3.val, NULL);
                            if (serv == NULL) {
                                $$->port = -1;
                            } else {
                                $$->port = htons(serv->s_port);
                            }
                        }
                        free((char *)$3.val);
                        break;
                    case TYPE:
                        $$->type = (strncasecmp((char *)$3.val, "bin", strlen("bin")) == 0);
                        free((char *)$3.val);
                        break;
                    case SUBPROTO:
                        $$->subproto = (char *)$3.val;
                        break;
                    case LOCALE:
                        $$->locale = (char *)$3.val;
                        break;
                    case ORIGINS:
                        $$->origins = (mod_websocket_origin_t *)$3.val;
                        break;
                    case PROTO:
                        $$->proto = (char *)$3.val;
                        break;
                    default:
                        break;
                    }
                }
                ;

assignment:
                KEY ASSIGN VALUE
                {
                    $$.val = (void *)$3;
                }
        |       KEY ASSIGN '(' origin ')'
                {
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
                PING_INTERVAL_CONFIG '=' VALUE
                {
                    websocket_config->ping_interval = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

timeout_config:
                TIMEOUT_CONFIG '=' VALUE
                {
                    websocket_config->timeout = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

debug_config:
                DEBUG_CONFIG '=' VALUE
                {
                    websocket_config->debug = (int)strtol($3, NULL, 10);
                    free((char *)$3);
                }
                ;

%%

mod_websocket_config_t *mod_websocket_config_parse(const char* fname) {
    FILE *fp = NULL;

    if ((fp = fopen(fname, "r"))  == NULL) {
        return NULL;
    }
    if (flock(fileno(fp), LOCK_SH) < 0) {
        fclose(fp);
        return NULL;
    }
    websocket_config = (mod_websocket_config_t *)malloc(sizeof(mod_websocket_config_t));
    if (websocket_config == NULL) {
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
    mod_websocket_backend_t *backend, *backend_next;
    mod_websocket_resource_t *resource, *resource_next;

    if (config == NULL) {
        return;
    }
    resource = config->resources;
    while (resource) {
        if (resource->key != NULL) {
            free(resource->key);
        }
        backend = resource->backends;
        while (backend) {
            if (backend->host != NULL) {
                free(backend->host);
            }
            if (backend->proto != NULL) {
                free(backend->proto);
            }
            if (backend->subproto != NULL) {
                free(backend->subproto);
            }
            if (backend->locale != NULL) {
                free(backend->locale);
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
            backend_next = backend->next;
            free(backend);
            backend = backend_next;
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
        fprintf(stderr, "config is null\n");
        return;
    }
    for (resource = config->resources; resource; resource = resource->next) {
        fprintf(stderr, "resource = [%s]\n", resource->key);
        for (backend = resource->backends; backend; backend = backend->next) {
            fprintf(stderr,
                    "\t(\n\t\thost = [%s]\n"
                    "\t\tport = [%d]\n"
                    "\t\ttype = [%d]\n"
                    "\t\tsubproto = [%s]\n"
                    "\t\tlocale = [%s]\n"
                    "\t\tproto = [%s]\n",
                    backend->host, backend->port, backend->type,
                    backend->subproto, backend->locale, backend->proto);
            fprintf(stderr, "\t\tallowed_origins = [ ");
            for (origin = backend->origins; origin; origin = origin->next) {
                fprintf(stderr, "[%s] ", origin->origin);
            }
            fprintf(stderr, "]\n\t)\n");
        }
    }
    return;
}

#if 0
int
main(int argc, char *argv[]) {
    mod_websocket_config_t* config = NULL;

    config = mod_websocket_config_parse(argv[1]);
    mod_websocket_config_print(config);
    mod_websocket_config_free(config);
    return 0;
}
#endif
