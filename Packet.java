public class Packet {
    private final String sourceIP;
    private final String destinationIP;
    private final int port;

    public Packet(String sourceIP, String destinationIP, int port) {
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.port = port;
    }

    public String getSourceIP() { 
        return sourceIP; 
    }
    public String getDestinationIP() {
         return destinationIP; 
    }
    public int getPort() {
         return port; 
    }

    @Override
    public String toString() {
        return sourceIP + " -> " + destinationIP + " : " + port;
    }
}
