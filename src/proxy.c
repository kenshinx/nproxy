
#include <jansson.h>
#include <hiredis.h>

#include "string.h"
#include "log.h"
#include "util.h"
#include "proxy.h"


np_proxy_t *
proxy_create(np_string *host, int port, np_string *proto, np_string *username, np_string *password)
{
    np_proxy_t *proxy;

    proxy = np_malloc(sizeof(*proxy));
    if (proxy == NULL) {
        return NULL;       
    }

    proxy->host = host;
    proxy->port = port;
    proxy->proto = proto;
    proxy->username = username;
    proxy->password = password;
    
    return proxy;
}

void
proxy_destroy(np_proxy_t *proxy)
{
    string_destroy(proxy->host);
    string_destroy(proxy->proto);
    string_destroy(proxy->username);
    string_destroy(proxy->password);
    np_free(proxy);
}

np_proxy_t *
proxy_from_json(const char *str)
{
    json_t *j;
    json_error_t error;
    void *kv;
    int port;

    np_string *host = string_null();
    np_string *proto = string_null();
    np_string *username = string_null();
    np_string *password = string_null();

    j = json_loads(str, 0, &error);
    if (!j) {
        log_error("json decode error %s: %s", str, error.text);
        return NULL;
    }

    for (kv = json_object_iter(j); kv; kv = json_object_iter_next(j, kv)) {
        json_t *tmp = json_object_iter_value(kv);
        
        if (strcmp(json_object_iter_key(kv), "host") == 0 && json_typeof(tmp) == JSON_STRING) {
            string_update(host, json_string_value(tmp)); 
        } else if (strcmp(json_object_iter_key(kv), "port") == 0 && json_typeof(tmp) == JSON_INTEGER) {
            port = json_integer_value(tmp);
        } else if (strcmp(json_object_iter_key(kv), "proto") == 0 && json_typeof(tmp) == JSON_STRING) {
            string_update(proto, json_string_value(tmp));
        } else if (strcmp(json_object_iter_key(kv), "username") == 0 && json_typeof(tmp) == JSON_STRING) {
            string_update(username, json_string_value(tmp));
        } else if (strcmp(json_object_iter_key(kv), "password") == 0 && json_typeof(tmp) == JSON_STRING) {
            string_update(password, json_string_value(tmp));
        }
    }

    return proxy_create(host, port, proto, username, password);
}

void
proxy_load_pool(np_array *pool, redisContext *c, char *key)
{
    redisReply      *reply;
    np_proxy_t      *proxy;
    unsigned int i;

    reply = redisCommand(c, "SMEMBERS %s", key);

    if (reply->type == REDIS_REPLY_ARRAY) {
        for (i = 0; i < reply->elements; i++) {
            proxy = proxy_from_json(reply->element[i]->str);
            if (proxy != NULL) {
                array_push(pool, proxy);
            }
        }
    }

    freeReplyObject(reply);
}

static void
proxy_print(np_proxy_t *proxy)
{
    log_notice("%s://%s:%d", proxy->proto->data, proxy->host->data, proxy->port);
}

void 
proxy_pool_dump(np_array *proxy_pool)
{
    log_notice("[Nproxy proxy pool]");
    array_foreach(proxy_pool, (array_foreach_func)&proxy_print);
}

