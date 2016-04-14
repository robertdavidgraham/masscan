Repo: https://github.com/agreene5/masscan
Fork of: https://github.com/robertdavidgraham/masscan

Changes made that are not applied to upstream as of 3/20:

- Added '--lockfile' / 'lockfile' to require an exclusive lock in order to run, helpful in
  preventing scans from an automated process running twice and flooding a network.
- Added '-N' and 'newlines' configuration options to use newlines instead of carriage returns 
  in the 'real-time' console output
- Fixed invalid JSON output when using -oJ
- Added timestamp value to JSON formatted output
- Fixed a bug in the unicornscan output module (my bug, oops!) that always reported 'open' 
  even when using 'show = open,closed' and the port was actually closed
- When only performing an ICMP scan, print ICMP scan beginning, not SYN scan beginning
- Added a small bit to the README about using setcap to remove the run as root requirement. 
  Whether there is a security net gain/loss is arguable but it's cleaner to run as a non-root
  user in many cases.
