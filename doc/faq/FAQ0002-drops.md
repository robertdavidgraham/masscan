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
equipment, causing the packets to be dropped, causing probes to fail.

As the issue #546 below indicates, they are experiencing this at very low
rates of less than 10,000 packets-per-second. That seems excessively low.
I assume the actual reason is because of policy enforcement limiting traffic
rates rather than overloading network equipment.



# Issues

- (#546 fast scan get result)[https://github.com/robertdavidgraham/masscan/issues/546]

