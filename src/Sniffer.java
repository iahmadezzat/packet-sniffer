import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.UIManager.*;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import jpcap.JpcapWriter;

import java.io.*;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

public class Sniffer extends JFrame {

    public Sniffer() {
        initComponents();
    }

    ThreadManager thread;
    static int INDEX = 0;
    static int ITERATOR = 0;
    static JpcapCaptor captor;
    private boolean isCapturing = false;
    static NetworkInterface[] NETWORK_INTERFACES;

    JpcapWriter writer = null;
    List<Packet> packets = new ArrayList<>();

    public static void main(String[] args) {
        try {
            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
        }
        EventQueue.invokeLater(() -> new Sniffer().setVisible(true));
    }

    void capture() {
        thread = new ThreadManager() {
            Object construct() {
                try {
                    captor = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, false, 20);

                    if ("UDP".equals(Objects.requireNonNull(filterOptions.getSelectedItem()).toString())) {
                        captor.setFilter("udp", true);
                    } else if ("TCP".equals(filterOptions.getSelectedItem().toString())) {
                        captor.setFilter("tcp", true);
                    } else if ("IP".equals(filterOptions.getSelectedItem().toString())) {
                        captor.setFilter("ip", true);
                    }

                    while (isCapturing) {
                        captor.processPacket(1, new Analyzer());
                        packets.add(captor.getPacket());
                    }
                    captor.close();

                } catch (Exception e) {
                    e.printStackTrace();
                }
                return 0;
            }

            public void finished() {
                this.interrupt();
            }
        };
        thread.start();
    }

    void analyzePacket() {
        Object obj = capturedPacketsTable.getModel().getValueAt(capturedPacketsTable.getSelectedRow(), 0);
        if (Analyzer.rowAnalyzer.get((int) obj)[3] == "TCP") {
            packetAnalyzerWindow.setText(
                    "Packet No: " + Analyzer.rowAnalyzer.get((int) obj)[0]
                            + "\nIP Version: " + Analyzer.rowAnalyzer.get((int) obj)[5]
                            + "\nSource IP: " + Analyzer.rowAnalyzer.get((int) obj)[1]
                            + "\nDestination IP: " + Analyzer.rowAnalyzer.get((int) obj)[2]
                            + "\nLength: " + Analyzer.rowAnalyzer.get((int) obj)[4]
                            + "\nProtocol: " + Analyzer.rowAnalyzer.get((int) obj)[3]
                            + "\n\nSource Port: " + Analyzer.rowAnalyzer.get((int) obj)[6]
                            + "\nDestination Port: " + Analyzer.rowAnalyzer.get((int) obj)[7]
                            + "\nSequence No: " + Analyzer.rowAnalyzer.get((int) obj)[8]
                            + "\n\nACK: " + Analyzer.rowAnalyzer.get((int) obj)[9]
                            + "\nACK No: " + Analyzer.rowAnalyzer.get((int) obj)[10]
                            + "\nWindow: " + Analyzer.rowAnalyzer.get((int) obj)[11]
                            + "\nUrgent: " + Analyzer.rowAnalyzer.get((int) obj)[12]
                            + "\nUrgent Pointer: " + Analyzer.rowAnalyzer.get((int) obj)[13]
                            + "\n\nHeader: " + Analyzer.rowAnalyzer.get((int) obj)[14]
                            + "\n\nData: " + Analyzer.rowAnalyzer.get((int) obj)[15]
            );
            try {
                hexViewWindow.setText(hexRefactoring(convertToHex(packetAnalyzerWindow.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (Analyzer.rowAnalyzer.get((int) obj)[3] == "UDP") {
            packetAnalyzerWindow.setText(
                    "Packet No: " + Analyzer.rowAnalyzer.get((int) obj)[0]
                            + "\nIP Version: " + Analyzer.rowAnalyzer.get((int) obj)[5]
                            + "\nSource IP: " + Analyzer.rowAnalyzer.get((int) obj)[1]
                            + "\nDestination IP: " + Analyzer.rowAnalyzer.get((int) obj)[2]
                            + "\nLength: " + Analyzer.rowAnalyzer.get((int) obj)[4]
                            + "\nProtocol: " + Analyzer.rowAnalyzer.get((int) obj)[3]
                            + "\n\nSource Port: " + Analyzer.rowAnalyzer.get((int) obj)[6]
                            + "\nDestination Port: " + Analyzer.rowAnalyzer.get((int) obj)[7]
                            + "\n\nHeader: " + Analyzer.rowAnalyzer.get((int) obj)[8]
                            + "\n\nData: " + Analyzer.rowAnalyzer.get((int) obj)[9]
            );

            try {
                hexViewWindow.setText(hexRefactoring(convertToHex(packetAnalyzerWindow.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else if (Analyzer.rowAnalyzer.get((int) obj)[3] == "IP") {
            packetAnalyzerWindow.setText(
                    "Packet No: " + Analyzer.rowAnalyzer.get((int) obj)[0]
                            + "\nIP Version: " + Analyzer.rowAnalyzer.get((int) obj)[5]
                            + "\nSource IP: " + Analyzer.rowAnalyzer.get((int) obj)[1]
                            + "\nDestination IP: " + Analyzer.rowAnalyzer.get((int) obj)[2]
                            + "\nLength: " + Analyzer.rowAnalyzer.get((int) obj)[4]
                            + "\n\nProtocol: " + Analyzer.rowAnalyzer.get((int) obj)[6]
                            + "\n\nOffset: " + Analyzer.rowAnalyzer.get((int) obj)[7]
                            + "\nHop Limit: " + Analyzer.rowAnalyzer.get((int) obj)[8]
                            + "\nPriority: " + Analyzer.rowAnalyzer.get((int) obj)[9]
                            + "\nFlow Label: " + Analyzer.rowAnalyzer.get((int) obj)[10]
                            + "\n\nHeader: " + Analyzer.rowAnalyzer.get((int) obj)[11]
                            + "\n\nData: " + Analyzer.rowAnalyzer.get((int) obj)[12]
            );

            try {
                hexViewWindow.setText(hexRefactoring(convertToHex(packetAnalyzerWindow.getText())));
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    static String convertToHex(String text) throws UnsupportedEncodingException {
        return DatatypeConverter.printHexBinary(text.getBytes(StandardCharsets.UTF_8));
    }

    static String hexRefactoring(String hex) {
        return hex.replaceAll("(.{32})", "$1\n").replaceAll("..(?!$)", "$0 ");
    }

    void printWriterExport() {
        try {
            File exportFile = new File("Export Data.txt");
            PrintWriter printWriter = new PrintWriter(exportFile);

            for (Packet packet : packets)
                if (packet != null) printWriter.println(packet.toString());

            printWriter.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void jWriterExport() {
        thread = new ThreadManager() {
            public Object construct() {
                writer = null;
                try {
                    captor = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, false, 20);
                    writer = JpcapWriter.openDumpFile(captor, "Export Data.txt");
                    for (int i = 0; i < ITERATOR; i++)
                        writer.writePacket(packets.get(i));
                    writer.close();
                } catch (IOException ex) {
                    Logger.getLogger(Sniffer.class.getName()).log(Level.SEVERE, null, ex);
                }
                return 0;
            }
            public void finished() {
                this.interrupt();
            }
        };
        thread.start();
    }

    public static Button stopButton;
    public static Button exportButton;
    public static Button captureButton;
    public static JTable capturedPacketsTable;
    public static JComboBox<String> filterOptions;
    private static JTextArea packetAnalyzerWindow;
    private static Button interfacesListButton;
    private static JTextArea hexViewWindow;

    // Generated using JFormDesigner Evaluation license - unknown
    private void initComponents() {
        JToolBar toolBar = new JToolBar();
        interfacesListButton = new Button();
        JLabel filterLabel = new JLabel();
        filterOptions = new JComboBox<>();
        captureButton = new Button();
        stopButton = new Button();
        exportButton = new Button();
        JScrollPane capturingPane = new JScrollPane();
        capturedPacketsTable = new javax.swing.JTable() {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JScrollPane packetAnalyzerPane = new JScrollPane();
        packetAnalyzerWindow = new JTextArea();
        JScrollPane hexViewPane = new JScrollPane();
        hexViewWindow = new JTextArea();
        JLabel packetAnalyzerLabel = new JLabel();
        JLabel hexViewLabel = new JLabel();

        captureButton.setEnabled(false);
        stopButton.setEnabled(false);
        exportButton.setEnabled(false);
        filterOptions.setEnabled(false);

        //======== this ========
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setTitle("Packet Sniffer Open Beta v1.0");
        setName("Packet Sniffer Open Beta v1.0");
        var contentPane = getContentPane();
        setResizable(false);

        //======== toolBar ========
        {
            toolBar.setRollover(true);

            //---- interfacesListButton ----
            interfacesListButton.setActionCommand("Interfaces");
            interfacesListButton.setBackground(new Color(30, 144, 255));
            interfacesListButton.setFont(new Font(Font.DIALOG, Font.BOLD, 12));
            interfacesListButton.setForeground(Color.white);
            interfacesListButton.setLabel("Interfaces");
            interfacesListButton.setPreferredSize(new Dimension(90, 26));
            interfacesListButton.addActionListener(this::interfacesListButtonAction);
            toolBar.add(interfacesListButton);

            //---- filterLabel ----
            filterLabel.setText(" Filter");
            toolBar.add(filterLabel);

            //---- filterOptions ----
            filterOptions.setModel(new DefaultComboBoxModel<>(new String[]{
                    "*",
                    "TCP",
                    "UDP",
                    "IP"
            }));
            filterOptions.setPreferredSize(new Dimension(320, 24));
//            filterOptions.addActionListener(this::filterOptionsAction);
            toolBar.add(filterOptions);

            //---- captureButton ----
            captureButton.setBackground(new Color(0, 128, 0));
            captureButton.setFont(new Font(Font.DIALOG, Font.BOLD, 12));
            captureButton.setForeground(Color.white);
            captureButton.setLabel("Capture");
            captureButton.setPreferredSize(new Dimension(83, 24));
            captureButton.addActionListener(this::captureButtonAction);
            toolBar.add(captureButton);

            //---- stopButton ----
            stopButton.setBackground(new Color(220, 20, 60));
            stopButton.setFont(new Font(Font.DIALOG, Font.BOLD, 12));
            stopButton.setForeground(Color.white);
            stopButton.setLabel("Stop");
            stopButton.setPreferredSize(new Dimension(83, 24));
            stopButton.addActionListener(this::stopButtonAction);
            toolBar.add(stopButton);

            //---- exportButton ----
            exportButton.setLabel("Export");
            exportButton.setPreferredSize(new Dimension(83, 24));
            exportButton.addActionListener(this::exportButtonAction);
            toolBar.add(exportButton);
        }

        //======== capturingPane ========
        {

            //---- capturedPacketsTable ----
            capturedPacketsTable.setModel(new DefaultTableModel(
                    new Object[][]{
                    },
                    new String[]{
                            "No.", "Source", "Destination", "Protocol", "Length"
                    }
            ) {
                final Class<?>[] columnTypes = new Class<?>[]{
                        Integer.class, Object.class, Object.class, Object.class, String.class
                };

                @Override
                public Class<?> getColumnClass(int columnIndex) {
                    return columnTypes[columnIndex];
                }
            });
            capturedPacketsTable.setRowHeight(20);
            capturedPacketsTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    capturedPacketMouseClicked(e);
                }
            });
            capturingPane.setViewportView(capturedPacketsTable);
        }

        //======== packetAnalyzerPane ========
        {

            //---- packetAnalyzerWindow ----
            packetAnalyzerWindow.setEditable(false);
            packetAnalyzerWindow.setColumns(20);
            packetAnalyzerWindow.setRows(5);
            packetAnalyzerPane.setViewportView(packetAnalyzerWindow);
        }

        //======== hexViewPane ========
        {
            hexViewPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

            //---- hexViewWindow ----
            hexViewWindow.setEditable(false);
            hexViewWindow.setColumns(20);
            hexViewWindow.setRows(5);
            hexViewPane.setViewportView(hexViewWindow);
        }

        //---- packetAnalyzerLabel ----
        packetAnalyzerLabel.setText("Packet Analyzer:");

        //---- hexViewLabel ----
        hexViewLabel.setText("Hex View:");

        GroupLayout contentPaneLayout = new GroupLayout(contentPane);
        contentPane.setLayout(contentPaneLayout);
        contentPaneLayout.setHorizontalGroup(
                contentPaneLayout.createParallelGroup()
                        .addComponent(capturingPane, GroupLayout.DEFAULT_SIZE, 703, Short.MAX_VALUE)
                        .addComponent(toolBar, GroupLayout.DEFAULT_SIZE, 703, Short.MAX_VALUE)
                        .addComponent(packetAnalyzerPane)
                        .addComponent(hexViewPane)
                        .addGroup(contentPaneLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(contentPaneLayout.createParallelGroup()
                                        .addComponent(packetAnalyzerLabel)
                                        .addComponent(hexViewLabel))
                                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        contentPaneLayout.setVerticalGroup(
                contentPaneLayout.createParallelGroup()
                        .addGroup(contentPaneLayout.createSequentialGroup()
                                .addComponent(toolBar, GroupLayout.PREFERRED_SIZE, 25, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(capturingPane, GroupLayout.PREFERRED_SIZE, 312, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(packetAnalyzerLabel, GroupLayout.PREFERRED_SIZE, 9, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(packetAnalyzerPane, GroupLayout.PREFERRED_SIZE, 140, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(hexViewLabel)
                                .addGap(1, 1, 1)
                                .addComponent(hexViewPane, GroupLayout.PREFERRED_SIZE, 108, GroupLayout.PREFERRED_SIZE))
        );
        pack();
        setLocationRelativeTo(getOwner());
    }

    private void capturedPacketMouseClicked(MouseEvent evt) {
        analyzePacket();
        hexViewWindow.setCaretPosition(0);
        packetAnalyzerWindow.setCaretPosition(0);
    }

    private void captureButtonAction(ActionEvent evt) {
        isCapturing = true;
        capture();
        exportButton.setEnabled(!isCapturing);
//        captureButton.setEnabled(!isCapturing);
        filterOptions.setEnabled(!isCapturing);
        interfacesListButton.setEnabled(!isCapturing);
    }

    private void stopButtonAction(ActionEvent evt) {
        isCapturing = false;
        thread.finished();
        exportButton.setEnabled(!isCapturing);
        captureButton.setEnabled(!isCapturing);
        filterOptions.setEnabled(!isCapturing);
        interfacesListButton.setEnabled(!isCapturing);
    }

    private void interfacesListButtonAction(ActionEvent evt) {
        new NetworkInterfaces();
    }

    private void exportButtonAction(ActionEvent evt) {
        printWriterExport();
//        jWriterExport();
    }
}