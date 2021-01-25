# Why are many results missing that I expect?

# Question

When I do a scan, results are missing that I know are there.
They show up when I repeat the scan, but then others are missing.
The faster I scan, the more results are missing.

# Answer

Network infrastructure does not like high rates of small packets.
Even though they can handle high **bit-rates** then cannot handle
high **packet-rates**.

This is what makes `masscan` so unique. It transmits packets at rates
far higher than other things can cope with. It often crashes networks.

Therefore, the faster you transmit packets, the more it overloads network
equipmen, causing the packets to be dropped, causing probes to fail.

