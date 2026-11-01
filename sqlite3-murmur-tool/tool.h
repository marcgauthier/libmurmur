#ifndef SQLITE3_MURMUR_TOOL_H
#define SQLITE3_MURMUR_TOOL_H

/* Private hooks for the generated upstream shell, not a library API. */
void murmur_tool_init(void);
void murmur_tool_usage(void);
int murmur_tool_status(int status);
void murmur_tool_exit_code(int status);
int murmur_tool_exiting(void);

#endif
