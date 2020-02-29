#import "audit_darwin.h"

// Hardcoded the size. We will probably never need this much.
// Will use Malloc in the future.
es_event_type_t eventSubscriptions[20];
int eventSubscriptionsSize = 0;

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
        ES_EVENT_TYPE_NOTIFY_CREATE
    };
    es_event_type_t process_monitor_events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT
    };
    switch (type) {
        case AUDIT_MONITOR_FILE:
            for(i = eventSubscriptionsSize, j = 0; j < (sizeof(file_monitor_events) / step_size); i++, j++) {
                eventSubscriptions[i] = file_monitor_events[j];
            }
            eventSubscriptionsSize += sizeof(file_monitor_events) / step_size;
            printArray(eventSubscriptions, eventSubscriptionsSize);
            break;
        case AUDIT_MONITOR_PROCESS:
            for(i = eventSubscriptionsSize, j = 0; j < (sizeof(file_monitor_events) / step_size); i++, j++) {
                eventSubscriptions[i] = process_monitor_events[j];
            }
            eventSubscriptionsSize += sizeof(process_monitor_events) / step_size;
            printArray(eventSubscriptions, eventSubscriptionsSize);
            break;
        default:
            *status = STATUS_ERROR;
            break;
    }
}