import jpcap.PacketReceiver;
import jpcap.packet.*;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;

public class Analyzer implements PacketReceiver {

    static IPPacket IP;
    static TCPPacket TCP;
    static UDPPacket UDP;

    public static List<Object[]> rowAnalyzer = new ArrayList<>();

    @Override
    public void receivePacket(Packet packet) {

        Object[] row = new Object[0];

        if (packet instanceof TCPPacket) {
            TCP = (TCPPacket) packet;

            row = new Object[]{Sniffer.ITERATOR, TCP.src_ip.toString().substring(1), TCP.dst_ip.toString().substring(1), "TCP", TCP.length};
            rowAnalyzer.add(new Object[]{Sniffer.ITERATOR, TCP.src_ip.toString().substring(1), TCP.dst_ip.toString().substring(1),
                    "TCP", TCP.length, TCP.version, TCP.src_port, TCP.dst_port, TCP.sequence, TCP.ack, TCP.ack_num, TCP.window,
                    TCP.urg, TCP.urgent_pointer, TCP.header, TCP.data});
        } else if (packet instanceof UDPPacket) {
            UDP = (UDPPacket) packet;

            row = new Object[]{Sniffer.ITERATOR, UDP.src_ip.toString().substring(1), UDP.dst_ip.toString().substring(1), "UDP", UDP.length};
            rowAnalyzer.add(new Object[]{Sniffer.ITERATOR, UDP.src_ip.toString().substring(1), UDP.dst_ip.toString().substring(1),
                    "UDP", UDP.length, UDP.version, UDP.src_port, UDP.dst_port, UDP.header, UDP.data});
        } else if (packet instanceof IPPacket) {
            IP = (IPPacket) packet;

            row = new Object[]{Sniffer.ITERATOR, IP.src_ip.toString().substring(1), IP.dst_ip.toString().substring(1), "IP", IP.length};
            rowAnalyzer.add(new Object[]{Sniffer.ITERATOR, IP.src_ip.toString().substring(1), IP.dst_ip.toString().substring(1),
                    "IP", IP.length, IP.version, IP.protocol, IP.offset, IP.hop_limit, IP.priority, IP.flow_label, IP.header, IP.data});
        }

        Sniffer.ITERATOR++;
        DefaultTableModel tableModel = (DefaultTableModel) Sniffer.capturedPacketsTable.getModel();
        tableModel.addRow(row);
    }
}
