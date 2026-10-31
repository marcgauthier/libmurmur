// Package fetchrestart is a local regression suite (no reference twin):
// in-process Stop/Start on a node that completed a file fetch must
// reopen the file store instead of failing with "File exists".
package fetchrestart
