/*
    Masscan scripting subsystem
*/
#ifndef SCRIPTING_H
#define SCRIPTING_H
#include "proto-banner1.h"
struct Masscan;

extern const struct ProtocolParserStream banner_scripting;

/**
 * Load the Lua scripting library and run the initialization
 * stage of all the specified scripts
 */
void scripting_init(struct Masscan *masscan);

/**
 * Create the "Masscan" object within the scripting subsystem
 */
void scripting_masscan_init(struct Masscan *masscan);

#endif

