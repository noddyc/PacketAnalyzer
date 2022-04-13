/**
 * This program is served as the IP class
 * @author    Jian He
 */
public class IP {
    /**
     * Index of protocol parts
     */
    private final static int VersionLength = 14;
    private final static int TypeOfService = 15;
    private final static int TotalLength1 = 16;
    private final static int TotalLength2 = 17;
    private final static int Identification1 = 18;
    private final static int Identification2 = 19;
    private final static int Flags = 20;
    private final static int FragmentOffset = 21;
    private final static int TimeToLive = 22;
    private final static int Protocol = 23;
    private final static int HeaderCheckSum1 = 24;
    private final static int HeaderCheckSum2 = 25;
    private final static int SourceAddress = 29;
    private final static int DestinationAddress = 33;
    private final static int Option = 34;


    /**
     * Constructor of IP class
     */
    public IP(){
    }

    /**
     * Identify the file is IP, UDP or ICMP
     * @param data  Integer array
     * @return  Integer
     */
    public int TypeIdentify(int[] data){
        int ProtocolType = data[Protocol];
        if(ProtocolType == 1){
            return 1;
        }else if(ProtocolType == 6){
            return 6;
        }else if(ProtocolType == 17){
            return 17;
        }else{
            return 0;
        }
    }

    /**
     * Print the header of IP
     * @param data Integer array
     * @return  Index of next protocol
     */
    public int PrintIPHeader(int[] data){
        StringBuilder IPHeader = new StringBuilder();
        IPHeader.append("IP:    ----- IP Header -----\n");
        IPHeader.append("IP:\n");

        StringBuilder VerLen = pktanalyzer.convert_hexa(data[VersionLength]);
        StringBuilder IPVersion = new StringBuilder("IP:    Version = " + VerLen.charAt(0) + "\n");
        IPHeader.append(IPVersion);
        StringBuilder IPLength = new StringBuilder("IP:    Header length = " +
                (Character.getNumericValue(VerLen.charAt(1)))*4 + " bytes\n");
        IPHeader.append(IPLength);

        IPHeader.append("IP:    Type of service = 0x" +
                pktanalyzer.convert_hexa(data[TypeOfService]) + "\n");
        StringBuilder TypeService = pktanalyzer.convert_binary(data[TypeOfService]);
        int Precedence = 0;
        for(int i = 0; i < 3; i++){
            Precedence += Character.getNumericValue(TypeService.charAt(i));
        }
        IPHeader.append("IP:        xxx. .... = " + Precedence + " (precedence)\n");

        if(TypeService.charAt(3) == '0'){
            IPHeader.append("IP:        ...0 .... = normal delay\n");
        }else{
            IPHeader.append("IP:        ...1 .... = low delay\n");
        }

        if(TypeService.charAt(4) == '0'){
            IPHeader.append("IP:        .... 0... = normal throughput\n");
        }else{
            IPHeader.append("IP:        .... 1... = high throughput\n");
        }

        if(TypeService.charAt(5) == '0'){
            IPHeader.append("IP:        .... .0.. = normal reliability\n");
        }else{
            IPHeader.append("IP:        .... .1.. = high reliability\n");
        }

        int Total_Length = 0;
        Total_Length += data[TotalLength1]*256;
        Total_Length += data[TotalLength2];
        IPHeader.append("IP:    Total length = " + Total_Length + " bytes\n");

        int Identification = 0;
        Identification += data[Identification1]*256;
        Identification += data[Identification2];
        IPHeader.append("IP:    Identification = " + Identification + "\n");

        int FlagFragmentSum = data[Flags]*256 + data[FragmentOffset];
        int FlagTotal = 0;
        int FragmentTotal = 0;
        for(int i = 15; i >= 0; i--){
            if(i == 15){
                FlagTotal +=  (FlagFragmentSum >>> i & 1) * 4;
            }else if(i == 14){
                FlagTotal +=  (FlagFragmentSum >>> i & 1) * 2;
            }else if(i == 13){
                FlagTotal +=  (FlagFragmentSum >>> i & 1);
            }else{
                FragmentTotal += (FlagFragmentSum >> i & 1) * (int) Math.pow(2, i);
            }
        }
        FragmentTotal *= 8;

        IPHeader.append("IP:    Flags = 0x" + FlagTotal + "\n");
        if(FlagTotal == 3){
            IPHeader.append("IP:        .1.. .... = do not fragment\n" +
                    "IP:        ..1. .... = more fragment\n");
        }
        if(FlagTotal == 2){
            IPHeader.append("IP:        .1.. .... = do not fragment\n" +
                    "IP:        ..0. .... = last fragment\n");
        }
        if(FlagTotal == 1){
            IPHeader.append("IP:        .0.. .... = may fragment\n" +
                    "IP:        ..1. .... = more fragment\n");
        }
        if(FlagTotal == 0){
            IPHeader.append("IP:        .0.. .... = may fragment\n" +
                    "IP:        ..0. .... = last fragment\n");
        }

        IPHeader.append("IP:    Fragment offset = " + FragmentTotal * 8 + " bytes\n");
        IPHeader.append("IP:    Time to live = " + data[TimeToLive] + " seconds/hops\n");

        int ProtocolType = data[Protocol];
        if(ProtocolType == 1){
            IPHeader.append("IP:    Protocol = " + ProtocolType + " (ICMP)\n");
        }
        if(ProtocolType == 6){
            IPHeader.append("IP:    Protocol = " + ProtocolType + " (TCP)\n");
        }
        if(ProtocolType == 17){
            IPHeader.append("IP:    Protocol = " + ProtocolType + " (UDP)\n");
        }

        StringBuilder HeaderCheckSum = pktanalyzer.convert_hexa(data[HeaderCheckSum1]).append(pktanalyzer.convert_hexa(data[HeaderCheckSum2]));
        IPHeader.append("IP:    Header checksum = 0x" + HeaderCheckSum + "\n");

        StringBuilder SrcAdd = new StringBuilder();
        for(int i = HeaderCheckSum2+1; i <= SourceAddress; i++){
            if(i != SourceAddress){
                SrcAdd.append(data[i]);
                SrcAdd.append(".");
            }else{
                SrcAdd.append(data[i]);
            }
        }
        IPHeader.append("IP:    Source address = " + SrcAdd + "\n");

        StringBuilder DestAdd = new StringBuilder();
        for(int i = SourceAddress+1; i <= DestinationAddress; i++){
            if(i != DestinationAddress){
                DestAdd.append(data[i]);
                DestAdd.append(".");
            }else{
                DestAdd.append(data[i]);
            }
        }
        IPHeader.append("IP:    Destination address = " + DestAdd + "\n");

        int difference = Character.getNumericValue(VerLen.charAt(1))*4 - 20;
        if(difference == 0){
            IPHeader.append("IP:    No options\n");
            IPHeader.append("IP:\n");
            System.out.println(IPHeader);
            return Option;
        }else{
            IPHeader.append("IP:    There is an option\n");
            System.out.println(IPHeader);
            IPHeader.append("IP:\n");
            return Option + difference;
        }
    }

}

