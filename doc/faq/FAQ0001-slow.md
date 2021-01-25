# Why is it not as fast as I expect?

## Question

Why is scanning speed only around 100,000 packets-per-second instead of a million packets-per-second?

## Answer

I don't know.

If you have the latest Linux distro on the latest hardware, you can sometime
see scanning speeds of 1 million packets-per-second, even when virtualized.

However, sometimes you also see only 100,000 packets-per-second.

I've spent a lot of time trying to diagnose this situation and cannot
figure out what's going on. The box I use in a colo does 500,000 packets-per-second.
A relatively slow machine in my home lab does 1.2 million packets-per-second.

The speed is determined by the operating system. The amount of CPU used by `masscan`
itself is insignificant.

My theory is various configuration options within the operating system that can make
packet tranmission very slow. Simple features that would not otherwise impact network
stacks that run at lower rates become really important at high rates.

One way around this is to install `PF_RING` and decidate a network adapter to packet
transmission completely bypassing the operating system. In that case, packet transmission
rates can reach 15 million packets-per-second.
