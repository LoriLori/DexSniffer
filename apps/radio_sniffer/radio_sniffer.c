/** radio_sniffer app:

This app shows the radio packets being transmitted by other Wixels on the
same channel.


== Description ==

A Wixel running this app appears to the USB host as a Virtual COM Port,
with USB product ID 0x2200.  To view the output of this app, connect to
the Wixel's virtual COM port using a terminal program.  Be sure to set your
terminal's line width to 120 characters or more to avoid line wrapping.
 
The app uses the radio_queue libray to receive packets.  It does not
transmit any packets.

The output from this app takes the following format:

147> "hello world!"       ! R: -50 L: 104 s:0 PING  p:0 0D0068656C6C6F20776F726C64212A68
 (1)      (2)            (3)  (4)    (5)  (6)  (7)  (8)    (9)

(1) index (line number)
(2) ASCII representation of packet contents (unprintable bytes are replaced with '?')
(3) '!' indicates packet failed CRC check
(4) RSSI
(5) LQI
(6) sequence bit (only applies to RF communications using radio_link)
(7) packet type (only applies to RF communications using radio_link)
(8) payload type (only applies to RF communications using radio_link)
(9) hexadecimal representation of raw packet contents, including length byte
    and any header bytes at beginning

The red LED indicates activity on the radio channel (packets being received).
Since every radio packet has a chance of being lost, there is no guarantee
that this app will pick up all the packets being sent, and some of
what it does pick up will be corrupted (indicated by a failed CRC check).


== Parameters ==

radio_channel: See description in radio_link.h.
*/

/** Dependencies **************************************************************/


#define DEBUG


#include <cc2511_map.h>
#include <board.h>
#include <random.h>
#include <time.h>


#include <usb.h>
#include <usb_com.h>
#include <radio_registers.h>
#include <radio_queue.h>
#include <gpio.h>

#include <uart1.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

extern int32 channel_number = 0;
extern volatile BIT channel_select = 0;
static volatile BIT do_verbose = 1;

static volatile BIT usbEnabled = 1;

// frequency offsets for each channel - seed to 0.
static uint8 fOffset[4] = {0xCE,0xD5,0xE6,0xE5};


uint8 lookup[16] = {
   0x0, 0x8, 0x4, 0xC,
   0x2, 0xA, 0x6, 0xE,
   0x1, 0x9, 0x5, 0xD,
   0x3, 0xB, 0x7, 0xF };

uint8 flip( uint8 n )
{
   return (lookup[n&0x0F] << 4) | lookup[n>>4];
}


uint32 dDecode(uint8 offset,uint8 XDATA * pkt) 
{
	uint32 rawValue = 0;
	
	rawValue = (flip (pkt[offset+1]) & 0x1F)<< 8;
	rawValue |= flip (pkt[offset]);
	rawValue = rawValue << ((flip (pkt[offset+1]) & 0xE0)>>5 );

	return rawValue;
}

/** Functions *****************************************************************/


void makeAllOutputs() {
    int i;
    for (i=0; i < 16; i++) {
        setDigitalOutput(i, LOW);
    }
}

// catch Sleep Timer interrupts
ISR (ST, 0) {
    IRCON &= ~0x80;  // clear IRCON.STIF
    SLEEP &= ~0x02;  // clear SLEEP.MODE
    IEN0 &= ~0x20;   // clear IEN0.STIE
    WORIRQ &= ~0x11; // clear Sleep timer EVENT0_MASK
                     // and EVENT0_FLAG
    WORCTRL &= ~0x03; // Set timer resolution back to 1 period.
}

void uartEnable() {
	if(!usbEnabled) {
	
		U1UCR |= 0x40; //CTS/RTS ON
		//P1 |= 0x20;
		//delayMs(1500);
		//U1CSR |= 0xc0;
		U1CSR |= 0x40; // Recevier enable
		U1UCR |= 0x40; //CTS/RTS ON
		
		P2 |= 0x02;
		P1 &= ~0x08;  
	}
}



void uartDisable() {
	if(!usbEnabled) {
		//U1UCR &= ~0x40; //CTS/RTS Off
		
		P1DIR |= 0x20;
		P1 |= 0x08;	
		//P1 &= ~0x20;
		//P2 &= ~0x02;
		//U1CSR &= ~0xC0;
		
		while(U1CSR&0x01  || uartTxPendingBytes()!=0)  {
			LED_RED(1);
		}
		U1CSR &= ~0x40; // Recevier disable
		//delayMs(1500);
	}
}

void goToSleep (uint16 seconds) {
    unsigned char temp;

	if(!usbEnabled) {
		LED_RED(1);
		//U1CSR &= 0x3F;
		
		// The wixel docs note that any input pins consume ~30uA
		//makeAllOutputs();

		IEN0 |= 0x20; // Enable global ST interrupt [IEN0.STIE]
		WORIRQ |= 0x10; // enable sleep timer interrupt [EVENT0_MASK]

		/* the sleep mode i've chosen is PM2.  According to the CC251132 datasheet,
		   typical power consumption from the SoC should be around 0.5uA */
		/*The SLEEP.MODE will be cleared to 00 by HW when power
		  mode is entered, thus interrupts are enabled during power modes.
		  All interrupts not to be used to wake up from power modes must
		  be disabled before setting SLEEP.MODE!=00.*/
		SLEEP |= 0x02;                  // SLEEP.MODE = PM2
		
		
		// Reset timer, update EVENT0, and enter PM2
		// WORCTRL[2] = Reset Timer
		// WORCTRL[1:0] = Sleep Timer resolution
		//                00 = 1 period
		//                01 = 2^5 periods
		//                10 = 2^10 periods
		//                11 = 2^15 periods

		// t(event0) = (1/32768)*(WOREVT1 << 8 + WOREVT0) * timer res
		// e.g. WOREVT1=0,WOREVT0=1,res=2^15 ~= 1 second 

		WORCTRL |= 0x04;  // Reset
		// Wait for 2x+ve edge on 32kHz clock
		temp = WORTIME0;
		while (temp == WORTIME0) {};
		temp = WORTIME0;
		while (temp == WORTIME0) {};

		WORCTRL |= 0x03; // 2^5 periods
		WOREVT1 = (seconds >> 8);
		WOREVT0 = (seconds & 0xff);

		PCON |= 0x01; // PCON.IDLE = 1;
		
		//U1CSR |= 0xc0;
		LED_RED(0);
	}
	else { //usbEnabled
		uint32 start = getMs();
		
		uint32 end = getMs();
		while(((end-start)/1000)<seconds) {
			end = getMs();
			LED_RED( ((getMs()/1000) % 2) == 0);
			delayMs(100);
			doServices();
			
		}
	
	}
}





void updateLeds()
{	
    usbShowStatusWithGreenLed();

    LED_YELLOW(radioQueueRxCurrentPacket());

    LED_RED(0);
}

// This is called by printf 
void putchar(char c)
{
	if(usbEnabled) {
		usbComTxSendByte(c);
	}
}

char nibbleToAscii(uint8 nibble)
{
    nibble &= 0xF;
    if (nibble <= 0x9){ return '0' + nibble; }
    else{ return 'A' + (nibble - 0xA); }
}


void toBytes(uint32 n,uint8 bytes[] ) {

	bytes[0] = (n >> 24) & 0xFF;
	bytes[1] = (n >> 16) & 0xFF;
	bytes[2] = (n >> 8) & 0xFF;
	bytes[3] = n & 0xFF;	
}

void printBytes(uint8 bytes[]) {
	int j;
	for(j = 0; j < 4; j++)  // add 1 for length byte
    {
		putchar(nibbleToAscii(bytes[j] >> 4));
		putchar(nibbleToAscii(bytes[j]));
		if(j<4) putchar('-');
	}

}

void printPacket(uint8 XDATA * pkt)
{
    static uint16 pkt_count = 0;
    uint8 j, len;
	uint8 bytes[4] = {0,0,0,0};
	
    len = pkt[0];

	if(do_verbose) {
		printf("%lu \t",getMs());

		// CRC ?
		putchar((pkt[len + 2] & 0x80) ? ' ' : '!');
		putchar(' ');

		// RSSI, LQI
		printf("R:%4d ", (int8)(pkt[len + 1])/2 - 71);
		printf("L:%4d ", pkt[len + 2] & 0x7F);
		printf("O:%4d ", FREQEST);
		printf("C:%4d ", CHANNR);

		// sequence number
		printf("s:%4d ", pkt[11] );

		// packet contents in hex // real data starts from 11
	 
		for(j = 12; j <= 15; j++)  // add 1 for length byte
		{
			putchar(nibbleToAscii(pkt[j] >> 4));
			putchar(nibbleToAscii(pkt[j]));
			if(j!=15) putchar('-');

		}
		printf("\t%lu \t%lu",dDecode(12,pkt),dDecode(14,pkt)*2);
		putchar('\r');
		putchar('\n');
	}
	
	
	

	if(!usbEnabled) {
	
		uartEnable();
		
		uart1TxSendByte(0x05);
		toBytes(dDecode(12,pkt),bytes);
		for(j = 0; j < 4; j++) {
			uart1TxSendByte(bytes[j]);
		}
		
		uart1TxSendByte(0x06);
		toBytes(dDecode(14,pkt)*2,bytes);
		for(j = 0; j < 4; j++) {
			uart1TxSendByte(bytes[j]);
		}
		
		uartDisable();
	}
	
	
}

uint8 SetRFParam(unsigned char XDATA* addr, uint8 val)
{

		
		*addr = val;
		
		return 1;
}



void swap_channel(uint8 ch)
{
	uint8 channels[4] ={0,100,199,209};
	
	if(do_verbose)
		printf("%lu Wait for idle\r\n",getMs());
	
    do {
      RFST = 4;   //SIDLE
    } while (MARCSTATE != 0x01);
  
    FSCTRL0 = fOffset[ch];
    CHANNR = channels[ch];
    
	RFST = 2;   //RX
	
	if(do_verbose) {
		printf("%lu Channel:  %d \r\n",getMs(),ch );
		printf("[%lu] %hhi %hhu \r\n",getMs(), MARCSTATE);
		
		
	}
}


#define WIDTH  (8 * sizeof(uint8))
#define TOPBIT (1 << (WIDTH - 1))
#define POLYNOMIAL 0xD8  /* 11011 followed by 0's */
uint8 crcSlow(uint8 const message[], int nBytes)
{
    uint8  remainder = 0;
	uint8 byte,bitt;
    for (byte = 0; byte < nBytes; ++byte)
    {
        remainder ^= (message[byte] << (WIDTH - 8));
        for (bitt = 8; bitt > 0; --bitt)
        {
            if (remainder & TOPBIT)
            {
                remainder = (remainder << 1) ^ POLYNOMIAL;
            }
            else
            {
                remainder = (remainder << 1);
            }
        }
    }
    return (remainder);

}   /* crcSlow() */

uint32 countblink=0;

 
uint32 t = 0x00000000; 
 
void sendTestNumber ()
{
	
	uint8 bytes[4] = {0,0,0,0};
	int j;

	uartEnable();
	toBytes(t,bytes);

	uart1TxSendByte(0x06);		
	for(j = 0; j < 4; j++) 
	{
		uart1TxSendByte(bytes[j]);
	}
	uartDisable();
	t++;
}
 
void doServices()
{
	if(usbEnabled) {
		boardService();
		usbComService();
	}
}

 // channel is the channel index = 0...3
int WaitForPacket(uint16 milliseconds, uint8 channel, uint8 XDATA * resultPacket)
{
	uint32 start = getMs();
	uint8 XDATA * packet = 0;
	int nRet = 0;
	
	swap_channel(channel);

	if(do_verbose)
		printf("[%lu] starting wait for packet on channel %d(%d) - will wait for %u ms\r\n", start, channel, (int)CHANNR, milliseconds);

	while (!milliseconds || (getMs() - start) < milliseconds)
	{
		doServices();
	
	
		LED_YELLOW( ((getMs()/250) % 4) == 0);
	
		if (packet = radioQueueRxCurrentPacket())
		{
			uint8 len = packet[0];
			
			if(radioCrcPassed())
			{
                int8 fOff = FREQEST;
				int8 fOffCh = fOffset[channel];

				fOffset[channel] += FREQEST;
				// there's a packet!
				//memcpy(pkt, packet, len+2); // +2 because we append RSSI and LQI to packet buffer, which isn't shown in len
				if(do_verbose) {
					printf("[%lu] received packet channel %d(%d) RSSI %d offset %02X bytes %hhu LQI %hhu\r\n", getMs(), channel, (int)CHANNR, radioRssi(), fOffset[channel], len,radioLqi());
                    printf("[%lu] %hhi %hhi \r\n",getMs(), fOff, fOffCh);
				}
				nRet = 0;
				memcpy(resultPacket, packet, 21); 
				if(do_verbose) {
					printPacket(packet);
					printPacket(resultPacket);
				}
			}
			else
			{
				if(do_verbose) {
					printf("[%lu] CRC failure channel %d(%d) RSSI %d %hhu bytes received LQI %hhu\r\n", getMs(), channel, (int)CHANNR, radioRssi(), len,radioLqi());
					printPacket(packet);
				}
			}
			
			
			// pull the packet off the queue
			radioQueueRxDoneWithPacket();
			return nRet;
		}
	}

	if(do_verbose)
		printf("[%lu] timed out waiting for packet on channel %d(%d)\r\n", getMs(), channel, (int)CHANNR);
	
	return nRet;
}

 
void printPacketIfNeeded()
{
	int delay = 0;								// initial delay is infinite (unless receive cancelled by protocol on USB)
	int nChannel = 0;
	uint8 XDATA goodPacket[21];
	
	memset(goodPacket, 0, 21);
	
	LED_RED(0);
	
	// start channel is the channel we initially do our infinite wait on.
	for(nChannel = 0; nChannel < 4; nChannel++)
	{
		// initial receive packet call blocks forever. 
		WaitForPacket(delay, nChannel,goodPacket);

		// ok, no packet this time, set new delay and try to next channel
		delay = 600;
	}

	printPacket(goodPacket);
	
	if(do_verbose) {
		printf("%lu Enter sleep\r\n",getMs());
		delayMs(1000);
	}
	
	goToSleep(270);
	if(do_verbose) {
		printf("%lu Wakeup from sleep\r\n",getMs());
	}
}


void test() {
	XDATA uint8  pkt[4] = {0x0E,0x1D,0x3F,0x19};
	uint32 rawValue = dDecode(0, pkt);
	
	printf("%lu\t",rawValue);
	rawValue = dDecode(2, pkt);
	printf("%lu\r\n",rawValue);
	
}

void test2() {
	uint32 t = 0xFFFFFFFF;
	uint8 bytes[4] = {0,0,0,0};
	int i;
	for(i=0;i<32;i++) {
	
		printf("%lu\t",t);
		toBytes(t,bytes);
		
		printBytes(bytes);
		printf("%d \r\n",crcSlow(bytes,4));
		t = t/2;
	}
}
  
void initUart1() {
	uart1Init();
	uart1SetBaudRate(115200);

}





void main()
{
	uint8 ch = 0;
	
	uint16 cnt = 0;
	
	
	
    systemInit();
    //usbInit();

	channel_select = 1;
	channel_number = 0;
	
	if(!usbEnabled) {
		initUart1();
		
		P1DIR |= 0x08; // RTS
		P2DIR |= 0x06; //RED LED
		
		uartEnable();
		uartDisable();
	}
	//makeAllOutputs();
	
    radioQueueInit();
    radioQueueAllowCrcErrors = 1;
	MCSM1 = 0;			// after RX go to idle, we don't transmit
	/*
	while(!usbComRxAvailable()) {
		boardService();
		usbComService();
		LED_RED(1);
		delayMs(50);
		LED_RED(0);
	}
	
	test2();
	*/
	swap_channel(0);
	
    while(1)
    {
        boardService();
        updateLeds();
        //usbComService();
		
		printPacketIfNeeded();
		
		//delayMs(100);
		LED_GREEN(0);
		
    }
}


