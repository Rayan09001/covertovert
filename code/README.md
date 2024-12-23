# Covert Storage Channel that exploits Protocol Field Manipulation using CWR Flag field in TCP [Code: CSC-PSV-TCP-CWR] 

This project implements a covert channel that exploits protocol field manipulation in TCP using the CWR flag. The covert channel is used to send hidden messages over a network, and the message is encoded using XOR with a key.

The channel works by modifying the CWR flag in the TCP header. The sender encodes binary data (XOR'd with a key) into the TCP flag field, and the receiver decodes the data by XOR'ing the CWR flag with the key to retrieve the original message. 

### `send` Function:
The `send` function generates a random binary message. It then XORs each byte of the message with a provided key and encodes the result into the CWR flag of the TCP packet. The packets are sent over the network with a delay specified by the `sleep_time`.

### `receive` Function:
The `receive` function listens for incoming TCP packets, extracts the CWR flag, and reconstructs the binary message. The message is decoded by XORing each byte with the same key used for encoding. The decoded message is logged once it reaches the end.

## Covert Channel Capacity

To calculate the covert channel capacity, the following steps were performed:

1. A binary message of length 128 bits was created.
2. A timer was started just before sending the first packet and stopped after the last packet was sent.
3. The difference in seconds between the start and end times was calculated.
4. The covert channel capacity was calculated by dividing the total number of bits (128) by the elapsed time in seconds.
5. The calculated covert channel capacity is **6 bits per second**.
