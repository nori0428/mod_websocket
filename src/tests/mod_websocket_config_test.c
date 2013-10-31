#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

#include "mod_websocket_config.h"

#define	TEST_FILE	"test.conf"

CU_TestFunc
mod_websocket_config_test() {
    mod_websocket_config_t* config = NULL;
    mod_websocket_resource_t *resource = NULL;
    mod_websocket_backend_t *backend = NULL;
    mod_websocket_origin_t *origin = NULL;
    int resource_count = 0, backend_count = 0, origin_count = 0;
    int test = 0;

    config = mod_websocket_config_parse(TEST_FILE);
    CU_ASSERT_PTR_NOT_NULL(config);
    CU_ASSERT_EQUAL(200, config->ping_interval);
    CU_ASSERT_EQUAL(200, config->timeout);
    CU_ASSERT_EQUAL(200, config->debug);
    for (resource = config->resources; resource; resource = resource->next) {
        backend_count = 0;
        CU_ASSERT_PTR_NOT_NULL(resource);
        resource_count++;
        CU_ASSERT_PTR_NOT_NULL(resource->key);
        if (strcasecmp(resource->key, "/res1") == 0) {
            test = 0;
        } else if (strcasecmp(resource->key, "/res2") == 0) {
            test = 1;
        } else if (strcasecmp(resource->key, "/res3") == 0) {
            test = 2;
        } else if (strcasecmp(resource->key, "/res4") == 0) {
            test = 3;
        } else if (strcasecmp(resource->key, "/comm") == 0) {
            test = 4;
        } else if (strcasecmp(resource->key, "/res0") == 0) {
            test = 5;
        } else if (strcasecmp(resource->key, "/proxy") == 0) {
            test = 6;
        } else {
            CU_FAIL("invalid resource");
            return;
        }
        for (backend = resource->backends; backend; backend = backend->next) {
            origin_count = 0;
            backend_count++;
            switch (test) {
            case 0:
                CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.1", backend->host));
                CU_ASSERT_EQUAL(1, backend->port);
                CU_ASSERT_EQUAL(0, backend->type);
                CU_ASSERT_PTR_NULL(backend->subproto);
                CU_ASSERT_PTR_NULL(backend->locale);
                CU_ASSERT_PTR_NULL(backend->origins);
                break;
            case 1:
                CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.2", backend->host));
                CU_ASSERT_EQUAL(2, backend->port);
                CU_ASSERT_EQUAL(0, backend->type);
                CU_ASSERT_EQUAL(0, strcasecmp("subproto2", backend->subproto));
                CU_ASSERT_EQUAL(0, strcasecmp("UTF-8", backend->locale));
                CU_ASSERT_PTR_NOT_NULL(backend->origins);
                break;
            case 2:
                CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.3", backend->host));
                CU_ASSERT_EQUAL(3, backend->port);
                CU_ASSERT_EQUAL(1, backend->type);
                CU_ASSERT_EQUAL(0, strcasecmp("subproto3", backend->subproto));
                CU_ASSERT_EQUAL(0, strcasecmp("UTF-8", backend->locale));
                CU_ASSERT_PTR_NOT_NULL(backend->origins);
                break;
            case 3:
                if (strcasecmp(backend->subproto, "subproto4") == 0) {
                    CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.4", backend->host));
                    CU_ASSERT_EQUAL(4, backend->port);
                    CU_ASSERT_EQUAL(1, backend->type);
                    CU_ASSERT_EQUAL(0, strcasecmp("UTF-8", backend->locale));
                    CU_ASSERT_PTR_NOT_NULL(backend->origins);
                } else if (strcasecmp(backend->subproto, "subproto5") == 0) {
                    CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.5", backend->host));
                    CU_ASSERT_EQUAL(4, backend->port);
                    CU_ASSERT_EQUAL(1, backend->type);
                    CU_ASSERT_EQUAL(0, strcasecmp("UTF-8", backend->locale));
                    CU_ASSERT_PTR_NOT_NULL(backend->origins);
                } else {
                    CU_FAIL("invalid backend");
                }
                break;
            case 4:
                CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.1", backend->host));
                CU_ASSERT_EQUAL(5, backend->port);
                CU_ASSERT_EQUAL(0, backend->type);
                CU_ASSERT_EQUAL(0, strcasecmp("subproto1", backend->subproto));
                CU_ASSERT_EQUAL(0, strcasecmp("UTF-8", backend->locale));
                CU_ASSERT_PTR_NULL(backend->origins);
                break;
            case 5:
                CU_ASSERT_EQUAL(0, strcasecmp("::1", backend->host));
                CU_ASSERT_EQUAL(1, backend->port);
                CU_ASSERT_EQUAL(0, backend->type);
                CU_ASSERT_PTR_NULL(backend->subproto);
                CU_ASSERT_PTR_NULL(backend->locale);
                CU_ASSERT_PTR_NULL(backend->origins);
                break;
            case 6:
                CU_ASSERT_EQUAL(0, strcasecmp("192.168.0.5", backend->host));
                CU_ASSERT_EQUAL(4, backend->port);
                CU_ASSERT_EQUAL(0, backend->type);
                CU_ASSERT_PTR_NULL(backend->subproto);
                CU_ASSERT_PTR_NULL(backend->locale);
                CU_ASSERT_PTR_NULL(backend->origins);
                CU_ASSERT_EQUAL(0, strcasecmp("websocket", backend->proto));
                break;
            default:
                CU_FAIL("invalid backend");
                break;
            }
            for (origin = backend->origins; origin; origin = origin->next) {
                switch (test) {
                case 1:
                    if (strcasecmp(origin->origin, "192.168.0.2") == 0) {
                        origin_count++;
                    } else if (strcasecmp(origin->origin, "res2.com") == 0) {
                        origin_count++;
                    } else {
                        CU_FAIL("invalid backend");
                    }
                    break;
                case 2:
                    if (strcasecmp(origin->origin, "192.168.0.3") == 0) {
                        origin_count++;
                    } else if (strcasecmp(origin->origin, "res3.com") == 0) {
                        origin_count++;
                    } else {
                        CU_FAIL("invalid backend");
                    }
                    break;
                case 3:
                    if (strcasecmp(origin->origin, "192.168.0.4") == 0) {
                        origin_count++;
                    } else if (strcasecmp(origin->origin, "res4.com") == 0) {
                        origin_count++;
                    } else {
                        CU_FAIL("invalid backend");
                    }
                    break;
                default:
                    CU_FAIL("invalid backend");
                    break;
                }
            }
            if (test != 0 && test != 4 && test != 5 && test != 6) {
                CU_ASSERT_EQUAL(2, origin_count);
            }
        }
        switch (test) {
        case 3:
            CU_ASSERT_EQUAL(2, backend_count);
            break;
        default:
            CU_ASSERT_EQUAL(1, backend_count);
            break;
        }
    }
    CU_ASSERT_EQUAL(7, resource_count);
}

int
main() {
    CU_ErrorCode ret;
    CU_pSuite suite;

    ret = CU_initialize_registry();
    if (ret != CUE_SUCCESS) {
        return -1;
    }
    CU_basic_set_mode(CU_BRM_SILENT);
    suite = CU_add_suite("mod_websocket_config_suite", NULL, NULL);
    CU_ADD_TEST(suite, mod_websocket_config_test);
    CU_basic_run_tests();
    ret = CU_get_number_of_failures();
    if (ret != 0) {
        CU_basic_show_failures(CU_get_failure_list());
        fprintf(stderr, "\n");
    }
    return ret;
}
