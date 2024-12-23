from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, sleep_time, key):
        """
        We encode the binary message by xor'ing with key given key should be 8 bit number in form of a string then we send the
        encoded byte bit by bit using CWR flag
        sleep_time : type int time between each package lower values may cause package loss recommended is 70
        key : type string 8 bit binary number
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]  
            xor_byte = format(int(byte, 2) ^ int(key, 2), '08b')  # xor with key given for encoding

            print(f"Sending XOR'd byte: {xor_byte} (Original: {byte})")

            for bit in xor_byte:
                cwr_flag = 0x80 if bit == '1' else 0x00  
                pkt = IP(dst="receiver%eth0") / TCP(flags=cwr_flag)
                send(pkt, verbose=False)
                time.sleep(sleep_time / 1000)
        
    
    def receive(self, log_file_name, key):
        """
        We receive encoded message bit by bit from CWR flag after we receive a byte we decode it by xor'ing with given key
        key : type string 8 bit binary number 
        """
        binary_message = ''
        message=''
        while True:
            pkt = sniff(count=1,filter="tcp", lfilter=lambda p: TCP in p )[0]
            if IP in pkt and TCP in pkt:
                cwr_flag = pkt[TCP].flags & 0x80
                bit = '1' if cwr_flag else '0'
                print(f"bit: {bit}")
            if bit is not None:
                binary_message += bit
                # End message when all bits of a byte are captured
                if len(binary_message) % 8 == 0:
                    char = (chr((int(binary_message[-8:], 2)) ^ int(key,2))) # xor with key given for decoding
                    message += char
                    print(f"Received char: {char}")
                    if char == '.':  # end of message
                        break
        self.log_message(message, log_file_name)
       
        
 