
import java.io.*;
import java.util.*;

public class LogReader {

    public static List<Packet> readPackets(String filename) {
        List<Packet> packets = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineNo = 0;
            while ((line = br.readLine()) != null) {
                lineNo++;
                line = line.trim();    
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                if (parts.length != 3) {
                    System.out.println("Skipping malformed line " + lineNo + ": " + line);
                    continue;
                }
                String src = parts[0];
                String dst = parts[1];
                int port;
            
                    port = Integer.parseInt(parts[2]);
                 
                packets.add(new Packet(src, dst, port));
            }
        } catch (FileNotFoundException e) {
            System.out.println("Input file not found: " + filename);
        } catch (IOException e) {
            System.out.println("Error reading file: " + e.getMessage());
        }
        return packets;
    }
}
