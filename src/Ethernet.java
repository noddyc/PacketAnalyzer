/**
 * This program is served as the ethernet class
 * @author    Jian He
 */
public class Ethernet {
    /**
     * Index of protocol parts
     */
    private final static int Dest = 6;
    private final static int Source = 12;
    private final static int Type = 14;


    /**
     * Print the header of ethernet
     * @param data Integer array
     * @param PacketSize Packet size
     */
    public void PrintEthernetHeader(int[] data, long PacketSize){
        StringBuilder EtherHeader = new StringBuilder();
        EtherHeader.append("ETHER:    ----- Ether Header -----\n");
        EtherHeader.append("ETHER:\n");
        EtherHeader.append("ETHER:    Packet size = " + PacketSize + " bytes\n");

        StringBuilder EtherDestination = new StringBuilder();
        for(int i = 0; i < Dest; i++){
            EtherDestination.append(pktanalyzer.convert_hexa(data[i]));
            if(i != Dest-1){
                EtherDestination.append(":");
            }
        }
        EtherHeader.append("ETHER:    Destination = " + EtherDestination + "\n");

        StringBuilder EtherSource = new StringBuilder();
        for(int i = Dest; i < Source; i++){
            EtherSource.append(pktanalyzer.convert_hexa(data[i]));
            if(i != Source-1){
                EtherSource.append(":");
            }
        }
        EtherHeader.append("ETHER:    Source = " + EtherSource + "\n");

        StringBuilder EtherType = new StringBuilder();
        EtherType.append("ETHER:    Ethertype = ");
        for(int i = Source; i < Type; i++){
            EtherType.append(pktanalyzer.convert_hexa(data[i]));
        }
        EtherType.append(" (ip) \n");
        EtherHeader.append(EtherType);
        EtherHeader.append("ETHER:\n");
        System.out.println(EtherHeader);
    }
}
