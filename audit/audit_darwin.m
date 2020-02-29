#import "audit_darwin.h"

es_event_type_t eventSubscriptions[] = {};

void enableMonitoringType(int type, int* status) {
    *status = STATUS_SUCCESS;
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
            NSLog(@"Auditing files...");
            break;
        case AUDIT_MONITOR_PROCESS:
            NSLog(@"Auditing processes...");
            break;
        default:
            NSLog(@"Unknown type");
            *status = STATUS_ERROR;
            break;
    }

}