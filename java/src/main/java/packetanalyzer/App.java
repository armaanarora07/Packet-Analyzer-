package packetanalyzer;

import packetanalyzer.api.ApiServer;
import packetanalyzer.dpi.DpiEngine;
import packetanalyzer.model.AppType;
import packetanalyzer.rules.RuleManager;

import java.io.File;

/**
 * Command-line entry point for the Java Packet Analyzer &amp; DPI System.
 *
 * <p>Usage examples:</p>
 * <pre>
 *   # Batch CLI Analysis:
 *   java -jar packet-analyzer.jar capture.pcap
 *   java -jar packet-analyzer.jar capture.pcap 100
 *   java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app YouTube
 *
 *   # Process PCAP and Launch REST API &amp; Web Dashboard:
 *   java -jar packet-analyzer.jar capture.pcap --server
 *   java -jar packet-analyzer.jar capture.pcap --server 8080
 *   java -jar packet-analyzer.jar capture.pcap filtered.pcap --server --port 8080 --block-domain *.tiktok.com
 * </pre>
 */
public class App {

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = null;
        int packetLimit = -1;
        boolean verbose = false;

        boolean startServer = false;
        int serverPort = 8080;

        RuleManager ruleManager = new RuleManager();
        String rulesFile = null;

        int argIndex = 1;

        // Check if argument 1 is an integer packet limit or an output file
        if (args.length >= 2) {
            try {
                packetLimit = Integer.parseInt(args[1]);
                argIndex = 2;
            } catch (NumberFormatException e) {
                if (!args[1].startsWith("--")) {
                    outputFile = args[1];
                    argIndex = 2;
                }
            }
        }

        // Parse remaining options
        while (argIndex < args.length) {
            String arg = args[argIndex];

            switch (arg) {
                case "--server", "--dashboard", "--serve" -> {
                    startServer = true;
                    if (argIndex + 1 < args.length) {
                        try {
                            serverPort = Integer.parseInt(args[argIndex + 1]);
                            argIndex++;
                        } catch (NumberFormatException ignored) {}
                    }
                }
                case "--port", "-p" -> {
                    if (argIndex + 1 < args.length) {
                        try {
                            serverPort = Integer.parseInt(args[++argIndex]);
                            startServer = true;
                        } catch (NumberFormatException ex) {
                            System.err.println("Warning: Invalid port number: " + args[argIndex]);
                        }
                    }
                }
                case "--block-ip" -> {
                    if (argIndex + 1 < args.length) {
                        ruleManager.blockIp(args[++argIndex]);
                    }
                }
                case "--block-app" -> {
                    if (argIndex + 1 < args.length) {
                        String appName = args[++argIndex];
                        AppType app = AppType.fromString(appName);
                        if (app != AppType.UNKNOWN) {
                            ruleManager.blockApp(app);
                        } else {
                            System.err.println("Warning: Unrecognized application name for blocking: " + appName);
                        }
                    }
                }
                case "--block-domain" -> {
                    if (argIndex + 1 < args.length) {
                        ruleManager.blockDomain(args[++argIndex]);
                    }
                }
                case "--block-port" -> {
                    if (argIndex + 1 < args.length) {
                        try {
                            ruleManager.blockPort(Integer.parseInt(args[++argIndex]));
                        } catch (NumberFormatException ex) {
                            System.err.println("Warning: Invalid port number: " + args[argIndex]);
                        }
                    }
                }
                case "--rules" -> {
                    if (argIndex + 1 < args.length) {
                        rulesFile = args[++argIndex];
                    }
                }
                case "--limit" -> {
                    if (argIndex + 1 < args.length) {
                        try {
                            packetLimit = Integer.parseInt(args[++argIndex]);
                        } catch (NumberFormatException ex) {
                            System.err.println("Warning: Invalid packet limit: " + args[argIndex]);
                        }
                    }
                }
                case "--verbose", "-v" -> verbose = true;
                case "--help", "-h" -> {
                    printUsage();
                    System.exit(0);
                }
                default -> System.err.println("Unknown option: " + arg);
            }
            argIndex++;
        }

        if (rulesFile != null) {
            ruleManager.loadRules(new File(rulesFile));
        }

        printBanner();
        System.out.println("Input PCAP:  " + inputFile);
        if (outputFile != null) {
            System.out.println("Output PCAP: " + outputFile);
        }
        if (packetLimit > 0) {
            System.out.println("Limit:       " + packetLimit + " packets");
        }
        System.out.println();

        DpiEngine engine = new DpiEngine(ruleManager);
        engine.setPacketLimit(packetLimit);
        engine.setVerbose(verbose);

        try {
            long startTime = System.currentTimeMillis();
            boolean success = engine.processFile(inputFile, outputFile);
            long elapsed = System.currentTimeMillis() - startTime;

            if (success) {
                System.out.println(engine.getStatsService().generateSummaryReport());
                System.out.println(engine.getStatsService().generateClassificationReport());
                System.out.println(String.format("Processing completed in %d ms.", elapsed));

                // Start REST API & Dashboard Server if requested
                if (startServer) {
                    ApiServer apiServer = new ApiServer(engine.getStatsService(), serverPort);
                    apiServer.start();

                    System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
                    System.out.println("║   🚀 DPI REST API & Web Dashboard Active                     ║");
                    System.out.println("╠══════════════════════════════════════════════════════════════╣");
                    System.out.println(String.format("║   Dashboard URL:  %-42s ║", apiServer.getBaseUrl() + "/"));
                    System.out.println("║   API Endpoints:                                             ║");
                    System.out.println(String.format("║     • GET %-49s ║", apiServer.getBaseUrl() + "/api/stats"));
                    System.out.println(String.format("║     • GET %-49s ║", apiServer.getBaseUrl() + "/api/flows"));
                    System.out.println("║                                                              ║");
                    System.out.println("║   Press Ctrl+C to terminate server.                          ║");
                    System.out.println("╚══════════════════════════════════════════════════════════════╝");

                    Runtime.getRuntime().addShutdownHook(new Thread(apiServer::stop));
                    Thread.currentThread().join();
                }
            } else {
                System.err.println("DPI processing encountered an error.");
                System.exit(1);
            }
        } catch (InterruptedException e) {
            System.out.println("\nServer shutdown requested. Exiting.");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("Fatal error processing PCAP: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║            JAVA PACKET ANALYZER & DPI ENGINE v1.0            ║");
        System.out.println("║            Deep Packet Inspection & Flow Classifier          ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private static void printUsage() {
        System.out.println("""
            Java Packet Analyzer & DPI Engine
            ==================================
            Usage:
              java -jar packet-analyzer.jar <input.pcap> [output.pcap or packet_limit] [options]

            Arguments:
              input.pcap              Source capture file to inspect
              output.pcap             (Optional) Destination file for forwarded packets
              packet_limit            (Optional) Maximum number of packets to process

            Options:
              --server [port]         Start REST API and Dashboard server (default port: 8080)
              --port <port>, -p       Port number for REST API and Dashboard server
              --block-ip <ip>         Block packets originating from specified IP
              --block-app <app>       Block application (YouTube, Facebook, Netflix, etc.)
              --block-domain <domain> Block domain name (supports wildcards, e.g. *.tiktok.com)
              --block-port <port>     Block destination TCP/UDP port
              --rules <file>          Load blocking rules from file
              --limit <n>             Limit processing to n packets
              --verbose, -v           Print real-time packet-by-packet logs
              --help, -h              Display this help message

            Supported Application Categories:
              Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
              Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare
            """);
    }
}
