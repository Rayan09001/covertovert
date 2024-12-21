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
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for bit in binary_message:
            cwr_flag = 0x80 if bit == '1' else 0x00  # CWR flag is the 8th bit in the TCP flags byte
            pkt = IP(dst="receiver%eth0") / TCP( flags=cwr_flag)
            print(f"bit: {bit}")
            send(pkt, verbose=False)
            time.sleep(30.0/1000)
        
    
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
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
                    char = chr(int(binary_message[-8:], 2))
                    message += char
                    print(f"Received char: {char}")
                    if char == '.':  # end of message
                        break
        self.log_message(message, log_file_name)
    
    
        
        
 