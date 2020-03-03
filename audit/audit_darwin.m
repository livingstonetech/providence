#import "audit_darwin.h"

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

/*----------------------------------------------------------------------------*/
/* Globals */
/*----------------------------------------------------------------------------*/
/*
 * Hardcoded the size. We will probably never need this much.
 * Will use Malloc in the future.
 */
es_event_type_t eventSubscriptions[20];
int eventSubscriptionsSize = 0;
es_client_t* client = nil;

CallbackBlock callbackBlock = ^(const es_message_t* message) {
    /* For some reason, processes halt if this is not there.
     * Haven't figured out why this is required for NOTIFY type events.
     */
    es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, true);
    goBridge(message);
};

/*----------------------------------------------------------------------------*/
/* End Globals */
/*----------------------------------------------------------------------------*/

// because I can't dlv into this
void printArray(es_event_type_t* arr, int size) {
    int i;
    printf("\n");
    for(i = 0; i < size; i++) 
        printf("%d | ", arr[i]);
}

void enableMonitoringType(int type, int* status) {
    *status = STATUS_SUCCESS;
    int step_size = sizeof(ES_EVENT_TYPE_NOTIFY_OPEN);
    int i, j;
    int events_array_size = 0;
    es_event_type_t file_monitor_events[] = {
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_LINK,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_SETOWNER,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_MOUNT,
        ES_EVENT_TYPE_NOTIFY_UNMOUNT
    };
    es_event_type_t process_monitor_events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
        ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD
    };
    switch (type) {
        case AUDIT_MONITOR_FILE:
            for(i = eventSubscriptionsSize, j = 0; j < (sizeof(file_monitor_events) / step_size); i++, j++) {
                eventSubscriptions[i] = file_monitor_events[j];
            }
            eventSubscriptionsSize += sizeof(file_monitor_events) / step_size;
            // printArray(eventSubscriptions, eventSubscriptionsSize);
            break;
        case AUDIT_MONITOR_PROCESS:
            for(i = eventSubscriptionsSize, j = 0; j < (sizeof(process_monitor_events) / step_size); i++, j++) {
                eventSubscriptions[i] = process_monitor_events[j];
            }
            eventSubscriptionsSize += sizeof(process_monitor_events) / step_size;
            // printArray(eventSubscriptions, eventSubscriptionsSize);
            break;
        default:
            *status = STATUS_ERROR;
            break;
    }
}

void startMonitoring(int* status) {
    *status = STATUS_SUCCESS;
    es_new_client_result_t result = 0;

    result = es_new_client(&client, ^(es_client_t* client, const es_message_t* message) {
        callbackBlock(message);
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        *status = STATUS_ERROR;
        switch (result) {
            case ES_NEW_CLIENT_RESULT_SUCCESS:
            // So all enums are switched, and the compiler doesn't cry.
            break;
            case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT");
            break;
            case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_INTERNAL");
            break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED");
            break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED");
            break;
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED");
            break;
            case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            NSLog(@"ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS");
            break;
        }
        // No need to go ahead.
        return;
    }
    
    if (ES_CLEAR_CACHE_RESULT_SUCCESS != es_clear_cache(client)) {
        *status = STATUS_ERROR;
        NSLog(@"Failed to clear cache. Exiting...");
        return;
    }

    if (ES_RETURN_SUCCESS != es_subscribe(client, eventSubscriptions, eventSubscriptionsSize)) {
        *status = STATUS_ERROR;
        NSLog(@"Failed to subscribe. Exiting...");
        return;
    }
    NSLog(@"All looks good. Looping forever...");
    [[NSRunLoop currentRunLoop] run];
}
