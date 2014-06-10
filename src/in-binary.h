#ifndef IN_BINARY_H
#define IN_BINARY_H
struct Masscan;

/**
 * Read that output of previous scans that were saved in the binary format
 * (i.e. using the -oB parameter or the '--output-format binary' parameter).
 * The intent is that the user can then re-output in another format like
 * JSON or XML.
 */
void
read_binary_scanfile(struct Masscan *masscan, 
                     int arg_first, int arg_max, char *argv[]);

#endif

