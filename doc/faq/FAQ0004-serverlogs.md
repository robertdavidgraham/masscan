# Why is masscan in my server logs?

## Question

Some example questions:
* Why is `masscan` appearing in my server logs?
* Why are you scanning me?
* Why is my server trying to connect to this github repo?

## Answer

When `masscan` connections to a webserver, it puts a link
back to this repo in the `User-Agent` field.

Since lots of people run Internet-wide scans using this tool,
and an Internet wide scan hits every public web server, you'll
see this appear in your web server logs several times a day.

It's the **end-to-end** principle of the Internet. Having a public
webserver on the Internet means that anybody can and will try to
connect to the web server.

It's nothing necessarily malicious. Lots of people run Internet-wide
scans to gather information about the state of the Internet. Of course,
some are indeed malicious, scanning to find vulnerabilities. However,
even when malicious, they probably aren't targetting you in particular,
but are instead scanning everybody.

