# The Yardstick One and RFcat Notes

As we covered in the Wireless Hacking video course, the Yardstick One is a very useful piece of hardware to perform testing of RF devices that communicate in frequencies under 1GHz. It can be combined with many tools, including RFcat. The following are a few links and resources that we discussed in the video course related to these tools:

## Yardstick One
* Yardstick One website: https://greatscottgadgets.com/2015/09-30-introducing-yard-stick-one/

## RFcat
* RFcat website: https://bitbucket.org/atlas0fd00m/rfcat


The following are several useful RFcat commands:
* `d._debug = 1` – dumps debug messages to the screen
* `d.debug()` - prints state information every second
* `d.discover()` - listens for specific SYNCWORDS
* `d.lowball()` - disables most “filters” to see more packets
* `d.lowballRestore()` - restores the configuration before calling lowball()
* `d.RFlisten()` - listens for signals and dumps data to the screen
* `d.RFcapture()` - dumps data to screen, returns list of packets
* `d.scan()` - scans a configurable frequency range 
* `d.setChannel()` - sets the channel to be used
* `d.setFHSSstate()` - sets the FHSS state to be used
* `d.setFreq()` - sets the frequency to be used
* `d.specan()` - a spectrum analyzer
* `print d.reprRadioConfig()` - prints the radio configuration details
