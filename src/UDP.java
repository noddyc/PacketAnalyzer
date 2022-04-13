/**
 * This program is served as the UDP class
 * @author    Jian He
 */
public class UDP {
    /**
     * Index of protocol parts
     */
    private int SourcePort1;
    private int SourcePort2;
    private int DestinationPort1;
    private int DestionationPort2;
    private int Length1;
    private int Length2;
    private int CheckSum1;
    private int CheckSum2;
    private int Data;

    /**
     * Constructor of the UDP class
     * @param StartingPoint Index of the UDP packet
     */
    public UDP(int StartingPoint){
        SourcePort1 = StartingPoint;
        SourcePort2 = SourcePort1+1;
        DestinationPort1 = SourcePort2+1;
        DestionationPort2 = DestinationPort1+1;
        Length1 = DestionationPort2+1;
        Length2 = Length1+1;
        CheckSum1 = Length2+1;
        CheckSum2 = CheckSum1+1;
        Data = CheckSum2+1;
    }

    /**
     * Print the header of UDP
     * @param data Integer array
     */
    public void PrintUDPHeader(int[] data){
        StringBuilder UDPHeader = new StringBuilder();
        UDPHeader.append("UDP:    ----- UDP Header -----\n");
        UDPHeader.append("UDP:\n");

        int SrcPort = 0;
        SrcPort += data[SourcePort1] * 256;
        SrcPort += data[SourcePort2];
        UDPHeader.append("UDP:    Source port = " + SrcPort + "\n");

        int DestPort = 0;
        DestPort += data[DestinationPort1] * 256;
        DestPort += data[DestionationPort2];

        UDPHeader.append("UDP:    Destination port = " + DestPort + "\n");

        int Length = 0;
        Length += data[Length1] * 256;
        Length += data[Length2];

        UDPHeader.append("UDP:    Length = " + Length + "\n");

        UDPHeader.append("UDP:    Checksum = 0x"+ pktanalyzer.convert_hexa(data[CheckSum1])
        + pktanalyzer.convert_hexa(data[CheckSum2]) + "\n");
        UDPHeader.append("UDP:    \n");

        System.out.println(UDPHeader);

        if(Data < data.length){
            int FirstPart = Data + 16;
            if(FirstPart < data.length){
                printUDPData(Data, FirstPart, data);
                int SecondPart = FirstPart + 16;
                if(SecondPart < data.length){
                    printUDPData(FirstPart, SecondPart, data);
                    int ThirdPart = SecondPart + 16;
                    if(ThirdPart < data.length) {
                        printUDPData(SecondPart, ThirdPart, data);
                        int FourthPart = ThirdPart + 16;
                        printUDPData(ThirdPart, Math.min(FourthPart, data.length), data);
                    }else{
                        printUDPData(SecondPart, data.length, data);
                    }
                }else{
                    printUDPData(FirstPart, data.length, data);
                }
            }else{
                printUDPData(Data, data.length, data);
            }
        }
    }

    /**
     * Print the UDP data
     * @param begin Begin index of the UDP data
     * @param end End index of the UDP data
     * @param data Integer array
     */
    public void printUDPData(int begin, int end, int[] data){
        StringBuilder sb =  new StringBuilder("UDP:    ");
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
