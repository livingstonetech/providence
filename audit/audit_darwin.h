/*
 * Code for managing lower level ESF stuff.
 * Primary purpose of this is to provide a callback function that can transfer
 * execution to Go once an event has been triggered.
 */
#ifndef AUDIT_DARWIN_H
#define AUDIT_DARWIN_H

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>

#define AUDIT_MONITOR_PROCESS       0x0
#define AUDIT_MONITOR_FILE          0x1

#define STATUS_ERROR                0x0
#define STATUS_SUCCESS              0x1

typedef void(^CallbackBlock)(const es_message_t* _Nonnull);

void enableMonitoringType(int, int* _Null_unspecified);
void startMonitoring(int* _Null_unspecified);

#endif