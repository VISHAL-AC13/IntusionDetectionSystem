import java.util.*;

public class IDS {

    private final int PORT_SCAN_THRESHOLD = 5;
    private final int DOS_THRESHOLD = 5;
    private final Map<String, Integer> requestCount = new HashMap<>();
    private final Map<String, Set<Integer>> portsUsed = new HashMap<>();
    private final List<String> alerts = new ArrayList<>();
    private final Map<String, Map<Integer, Integer>> portCounts = new HashMap<>();

    public void analyze(Packet p) {
        String src = p.getSourceIP();
        int port = p.getPort();
        int newCount = requestCount.getOrDefault(src, 0) + 1;
        requestCount.put(src, newCount);
        portsUsed.putIfAbsent(src, new HashSet<>());
        portsUsed.get(src).add(port);

        portCounts.putIfAbsent(src, new HashMap<>());
        Map<Integer, Integer> perPort = portCounts.get(src);
        perPort.put(port, perPort.getOrDefault(port, 0) + 1);
        int uniquePorts = portsUsed.get(src).size();
        if (uniquePorts >= PORT_SCAN_THRESHOLD) {
            String msg = "ALERT: Port scan suspected from " + src + " (unique ports = " + uniquePorts + ")";
            if (!alerts.contains(msg)) {
                System.out.println(msg);
                alerts.add(msg);
            }
        }


        if (newCount >= DOS_THRESHOLD) {
            int mostUsedPort = mostUsedPortForSource(src);
            String msg;
            if (mostUsedPort == -1) {
                msg = "ALERT: Possible DoS attack from " + src + " (requests = " + newCount + ")";
            } else {
                msg = "ALERT: Possible DoS attack from " + src + " (requests = " + newCount + ", most-used port = " + mostUsedPort + ")";
            }
            if (!alerts.contains(msg)) {
                System.out.println(msg);
                alerts.add(msg);
            }
        }
    }

    private int mostUsedPortForSource(String src) {
        Map<Integer, Integer> perPort = portCounts.get(src);
        if (perPort == null || perPort.isEmpty()) return -1;
        int bestPort = -1;
        int bestCount = -1;
        for (Map.Entry<Integer, Integer> e : perPort.entrySet()) {
            int p = e.getKey();
            int c = e.getValue();
            if (c > bestCount) {
                bestCount = c;
                bestPort = p;
            }
        }
        return bestPort;
    }

    public Map<String, Integer> getRequestCount() {
        return Collections.unmodifiableMap(requestCount);
    }

    public Map<String, Set<Integer>> getPortsUsed() {
        return Collections.unmodifiableMap(portsUsed);
    }

    public List<String> getAlerts() {
        return Collections.unmodifiableList(alerts);
    }


    public Map<String, Map<Integer, Integer>> getPortCounts() {
        Map<String, Map<Integer, Integer>> copy = new HashMap<>();
        for (Map.Entry<String, Map<Integer, Integer>> e : portCounts.entrySet()) {
            copy.put(e.getKey(), Collections.unmodifiableMap(e.getValue()));
        }
        return Collections.unmodifiableMap(copy);
    }

    public void printSummary() {
        System.out.println("Total distinct sources: " + requestCount.size());
        System.out.println("Requests per IP:");
        for (Map.Entry<String, Integer> e : requestCount.entrySet()) {
            System.out.println("  " + e.getKey() + " -> " + e.getValue());
        }
        System.out.println("\nPorts used per IP:");
        for (Map.Entry<String, Set<Integer>> e : portsUsed.entrySet()) {
            System.out.println("  " + e.getKey() + " -> " + e.getValue());
        }
        System.out.println("\nPer-source port counts:");
        for (Map.Entry<String, Map<Integer, Integer>> e : portCounts.entrySet()) {
            System.out.println("  " + e.getKey() + " -> " + e.getValue());
        }
        System.out.println("\nAlerts generated:");
        if (alerts.isEmpty()) {
            System.out.println("  (none)");
        } else {
            for (String a : alerts) System.out.println("  " + a);
        }
    }
}
