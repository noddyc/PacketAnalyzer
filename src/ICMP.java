/**
 * This program is served as the ICMP class
 * @author    Jian He
 */
public class ICMP {
    /**
     * Index of protocol parts
     */
    int Type;
    int Code;
    int CheckSum1;
    int CheckSum2;

    /**
     * Constructor of the ICMP class
     * @param StartingPoint Index of the ICMP packet
     */
    public ICMP(int StartingPoint){
        Type = StartingPoint;
        Code = Type+1;
        CheckSum1 = Code+1;
        CheckSum2 = CheckSum1+1;
    }

    /**
     * Print the header of ICMP
     * @param data Integer array
     */
    public void PrintICMPHeader(int[] data){
        StringBuilder ICMPHeader = new StringBuilder();
        ICMPHeader.append("ICMP:    ----- ICMP Header -----\n");
        ICMPHeader.append("ICMP:\n");
        int ICMPType = data[Type];
        if(ICMPType == 0){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Echo Reply)\n");
        }else if(ICMPType == 3){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Destination Unreachable)\n");
        }else if(ICMPType == 4){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Source Quench)\n");
        }else if(ICMPType == 5){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Redirect Message)\n");
        }else if(ICMPType == 8){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Echo Request)\n");
        }else if(ICMPType == 9){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Router Advertisement)\n");
        }else if(ICMPType == 10){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Router Solicitation)\n");
        }else if(ICMPType == 11){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Time Exceeded)\n");
        }else if(ICMPType == 12){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Parameter Problem)\n");
        }else if(ICMPType == 13){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Timestamp)\n");
        }else if(ICMPType == 14){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Timestamp Reply)\n");
        }else if(ICMPType == 42){
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Extended Echo Request)\n");
        }else{
            ICMPHeader.append("ICMP:    Type = " + ICMPType + " (Unidentified)\n");
        }
        ICMPHeader.append("ICMP:    Code = " + data[Code] + "\n");
        ICMPHeader.append("ICMP:    Checksum = 0x" + pktanalyzer.convert_hexa(data[CheckSum1])
                + pktanalyzer.convert_hexa(data[CheckSum2]) + "\n");
        ICMPHeader.append("ICMP:\n");
        System.out.println(ICMPHeader);
    }
}
