import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * This program is served as the pktanalyzer
 * @author    Jian He
 */
public class pktanalyzer {
    /**
     * This is to read the binary file
     * @param args path of the binary file
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        if(args.length != 1){
            System.out.println("Usage: java pktanalyzer path of binaryfile");
            System.exit(0);
        }
        FileInputStream Stream = new FileInputStream(args[0]);
        int FileSize = Stream.available();
        byte[] Data = new byte[FileSize];
        Stream.read(Data);
        Stream.close();
        int[] DataPostive = new int[Data.length];
        for(int i = 0; i < Data.length; i++){
            if(Data[i] < 0){
                DataPostive[i] = (Data[i] + 256);
            }else{
                DataPostive[i] = Data[i];
            }
        }
        File file = new File(args[0]);
        long Size = file.length();

        // Create ethernet header
        Ethernet ethernet = new Ethernet();
        ethernet.PrintEthernetHeader(DataPostive, Size);

        // Create ip header
        IP ip = new IP();
        int location = ip.PrintIPHeader(DataPostive);
        int type = ip.TypeIdentify(DataPostive);

        // Create TCP, ICMP or UDP header
        if(type == 6){
            TCP tcp = new TCP(location);
            tcp.PrintTCPHeader(DataPostive);
        }

        if(type == 1){
            ICMP icmp = new ICMP(location);
            icmp.PrintICMPHeader(DataPostive);
        }

        if(type == 17){
            UDP udp = new UDP(location);
            udp.PrintUDPHeader(DataPostive);
        }
    }

    /**
     * Convert an Integer to Hexadecimal
     * @param data Integer
     * @return Hexadecimal
     */
    public static StringBuilder convert_hexa(int data){
        char[] chs = {'0', '1', '2', '3', '4', '5', '6',
                '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        int num = data;
        StringBuilder Result = new StringBuilder();
        while(num != 0){
            Result.insert(0, chs[num & 15]);
            num = num >>> 4;
        }
        while(Result.length() < 2){
            Result.insert(0, "0");
        }
        return Result;
    }

    /**
     * Convert an Integer to Binary number
     * @param data Integer
     * @return Binary number
     */
    public static StringBuilder convert_binary(int data){
        StringBuilder Result = new StringBuilder();
        for(int i = 7; i >= 0; i--){
            Result.append(data >>> i & 1);
        }
        return Result;
    }
}
