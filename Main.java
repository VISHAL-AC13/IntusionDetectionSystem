import java.util.*;

public class Main {
    public static void main(String[] args) {
        String filename = "Alert.txt"; 
        System.out.println("Reading packets from: " + filename);

        List<Packet> packets = LogReader.readPackets(filename);
        if (packets.isEmpty()) {
            System.out.println("No packets to process. Exiting.");
            return;
        }

        IDS ids = new IDS();

        
        for (Packet p : packets) {
            ids.analyze(p);
        }

        ids.printSummary();
       
    }
}
