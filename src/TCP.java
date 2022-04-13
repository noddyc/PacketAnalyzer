/**
 * This program is served as the TCP class
 * @author    Jian He
 */
public class TCP {
    /**
     * Index of protocol parts
     */
    private int SourcePort1;
    private int SourcePort2;
    private int DestinationPort1;
    private int DestinationPort2;
    private int SequenceNumber;
    private int AckNumber;
    private int DataOffset;
    private int Flags;
    private int Window1;
    private int Window2;
    private int Checksum1;
    private int Checksum2;
    private int UrgentPointer1;
    private int UrgentPointer2;
    private int Options;

    /**
     * Constructor of the TCP class
     * @param StartingPoint Index of the TCP packet
     */
    public TCP(int StartingPoint){
        SourcePort1 = StartingPoint;
        SourcePort2 = SourcePort1+1;
        DestinationPort1 = SourcePort2+1;
        DestinationPort2 = DestinationPort1+1;
        SequenceNumber = DestinationPort2+4;
        AckNumber = SequenceNumber+4;
        DataOffset = AckNumber+1;
        Flags = DataOffset+1;
        Window1 = Flags+1;
        Window2 = Window1+1;
        Checksum1 = Window2+1;
        Checksum2 = Checksum1+1;
        UrgentPointer1 = Checksum2+1;
        UrgentPointer2 = UrgentPointer1+1;
    }

    /**
     * Print the header of TCP
     * @param data Integer array
     */
    public void PrintTCPHeader(int[] data) {
        Boolean urgent = false;
        StringBuilder TCPHeader = new StringBuilder();
        TCPHeader.append("TCP:    ---- TCP Header ----\n");
        TCPHeader.append("TCP:    \n");

        int SrcPort = 0;
        SrcPort += data[SourcePort1] * 256;
        SrcPort += data[SourcePort2];

        TCPHeader.append("TCP:    Source port = " + SrcPort + "\n");

        int DestPort = 0;
        DestPort += data[DestinationPort1] * 256;
        DestPort += data[DestinationPort2];

        TCPHeader.append("TCP:    Destination port = " + DestPort + "\n");

        int Sequence = 0;
        int Counter = 3;
        for (int i = DestinationPort2 + 1; i <= SequenceNumber; i++) {
            Sequence += (int) Math.pow(256, Counter) * data[i];
            Counter--;
        }
        TCPHeader.append("TCP:    Sequence number = " + Sequence + "\n");

        long Ack = 0;
        Counter = 3;
        for (int i = SequenceNumber + 1; i <= AckNumber; i++) {
            Ack += (long) Math.pow(256, Counter) * data[i];
            Counter--;
        }
        TCPHeader.append("TCP:    Acknowledgement number = " + Ack + "\n");

        StringBuilder DataOffSet = pktanalyzer.convert_hexa(data[DataOffset]);
        int DOS = Character.getNumericValue(DataOffSet.charAt(0));
        TCPHeader.append("TCP:    Data offset = " + DOS * 4 + " bytes\n");

        TCPHeader.append("TCP:    Flags = 0x" + pktanalyzer.convert_hexa(data[Flags]) + "\n");
        StringBuilder FlagStr = pktanalyzer.convert_binary(data[Flags]);
        for (int i = 2; i < FlagStr.length(); i++) {
            if (i == 2) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        ..0. .... = No urgent pointer\n");
                    urgent = false;
                } else {
                    TCPHeader.append("TCP:        ..1. .... = Urgent pointer\n");
                    urgent = true;
                }
            }
            if (i == 3) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        ...0 .... = No Acknowledgement\n");
                } else {
                    TCPHeader.append("TCP:        ...1 .... = Urgent pointer\n");
                }
            }
            if (i == 4) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        .... 0... = No push\n");
                } else {
                    TCPHeader.append("TCP:        .... 1... = Push\n");
                }
            }
            if (i == 5) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        .... .0.. = No reset\n");
                } else {
                    TCPHeader.append("TCP:        .... .1.. = Reset\n");
                }
            }
            if (i == 6) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        .... ..0. = No Syn\n");
                } else {
                    TCPHeader.append("TCP:        .... ..1. = Syn\n");
                }
            }
            if (i == 7) {
                if (Character.getNumericValue(FlagStr.charAt(i)) == 0) {
                    TCPHeader.append("TCP:        .... ...0 = No Fin\n");
                } else {
                    TCPHeader.append("TCP:        ..,. ...1 = Fin");
                }
            }
        }
        int Window = 0;
        Window += data[Window1] * 256;
        Window += data[Window2];
        TCPHeader.append("TCP:    Window = " + Window + "\n");

        TCPHeader.append("TCP:    Checksum = 0x" + pktanalyzer.convert_hexa(data[Checksum1]) +
                pktanalyzer.convert_hexa(data[Checksum2]) + "\n");

        if (urgent) {
            TCPHeader.append("TCP:    Urgent pointer = " + data[UrgentPointer1] +
                    data[UrgentPointer2] + "\n");
        } else {
            TCPHeader.append("TCP:    Urgent pointer = 0\n");
        }
        //Options
        if (DOS * 4 > 20) {
            TCPHeader.append("TCP:    There is an option\n");
            this.Options = UrgentPointer2 + 1 + (DOS * 4 - 20);
        } else {
            TCPHeader.append("TCP:    No options\n");
            this.Options = UrgentPointer2 + 1;
        }


        TCPHeader.append("TCP:    \n");
        TCPHeader.append("TCP:    Data: (first 64 bytes)");
        System.out.println(TCPHeader);

        if (Options < data.length) {
            int FirstPart = Options + 16;
            if (FirstPart < data.length) {
                printTCPData(Options, FirstPart, data);
                int SecondPart = FirstPart + 16;
                if (SecondPart < data.length) {
                    printTCPData(FirstPart, SecondPart, data);
                    int ThirdPart = SecondPart + 16;
                    if (ThirdPart < data.length) {
                        printTCPData(SecondPart, ThirdPart, data);
                        int FourthPart = ThirdPart + 16;
                        printTCPData(ThirdPart, Math.min(FourthPart, data.length), data);
                    } else {
                        printTCPData(SecondPart, data.length, data);
                    }
                } else {
                    printTCPData(FirstPart, data.length, data);
                }
            } else {
                printTCPData(Options, data.length, data);
            }
        }
    }

    /**
     * Print the TCP data
     * @param begin Begin index of the TCP data
     * @param end End index of the TCP data
     * @param data Integer array
     */
    public void printTCPData(int begin, int end, int[] data){
        StringBuilder sb =  new StringBuilder("TCP:    ");
        StringBuilder ascii = new StringBuilder("'");
        for(int i = begin; i < end; i+=2){
            sb.append(pktanalyzer.convert_hexa(data[i]));
            ascii.append(convertAscii(data[i]));
            if(i+1 < end){
                sb.append(pktanalyzer.convert_hexa(data[i+1]));
                ascii.append(convertAscii(data[i+1]));
            }
            sb.append(" ");
        }
        ascii.append("'");
        System.out.println(sb + "    " + ascii);
    }

    /**
     * Convert integer to ascii character
     * @param number Integer
     * @return Character
     */
    public char convertAscii(int number){
        if(number >= 33 && number <= 127){
            return (char) Integer.parseInt(pktanalyzer.convert_hexa(number).toString(), 16);
        }else{
            return '.';
        }
    }
}
