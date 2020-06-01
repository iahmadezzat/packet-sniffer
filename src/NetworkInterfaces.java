import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.UIManager.*;
import java.util.logging.*;

import jpcap.*;

public class NetworkInterfaces extends JFrame {

    private static int COUNTER = 0;
    private String interfacesData = "";

    public NetworkInterfaces() {
        ListNetworkInterfaces();
        initComponents();
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        selectionTextField.requestFocus();
    }

    public void ListNetworkInterfaces() {

        interfacesData += "\t<table style=\"width:100%; border: 1px solid black; border-collapse: collapse;\">\n" +
                "  <tr>\n" +
                "    <th align=\"center\" width=\"10%;\" style=\"border: 1px solid black;\">#</th>\n" +
                "      <th align=\"center\" width=\"90%;\" style=\"border: 1px solid black;\">Network Interface Data</th>\n" +
                "  </tr>\n";

        Sniffer.NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
        for (int i = 0; i < Sniffer.NETWORK_INTERFACES.length; i++) {

            interfacesData += "<tr>\n";
            interfacesData += "<td align=\"center\" style=\"padding-top: 7px; border: 1px solid black;\">" + "<h1>" + i + "</h1>" + "</td>\n";
            interfacesData += "<td align=\"left\" style=\"padding-top: 7px; border: 1px solid black;\"><u>Name</u>: " + Sniffer.NETWORK_INTERFACES[i].name.substring(1) + "<br/>\n";
            interfacesData += "<u>Description</u>: <b>" + Sniffer.NETWORK_INTERFACES[i].description + "</b><br/>\n";
            interfacesData += "<u>DataLink Name</u>: " + Sniffer.NETWORK_INTERFACES[i].datalink_name + "<br/>\n";
            interfacesData += "<u>DataLink Description</u>: " + Sniffer.NETWORK_INTERFACES[i].datalink_description + "<br/>\n";

            interfacesData += "<u>MAC Address</u>: ";
            byte[] macAddress = Sniffer.NETWORK_INTERFACES[i].mac_address;
            for (int j = 0; j < Sniffer.NETWORK_INTERFACES.length - 1; j++)
                interfacesData += Integer.toHexString(macAddress[j] & 0xff) + ":";
            interfacesData += "<br/>\n";

            NetworkInterfaceAddress[] NIA = Sniffer.NETWORK_INTERFACES[i].addresses;
            interfacesData += "<u>IP Address</u>: " + NIA[1].address.toString().substring(1) + "<br/>\n";
            interfacesData += "<u>Subnet Mask</u>: " + NIA[1].subnet + "<br/>\n";
            interfacesData += "<u>Broadcast Address</u>: " + NIA[1].broadcast + "<br/>\n";
            interfacesData += "\t </td>\n" + "</tr>\n";

            COUNTER++;
        }
        interfacesData += "</table>";
    }

    public void ChooseInterface() {

        int choice = Integer.parseInt(selectionTextField.getText());
        if (choice >= 0 && choice < COUNTER) {
            Sniffer.INDEX = choice;
            Sniffer.captureButton.setEnabled(true);
            Sniffer.filterOptions.setEnabled(true);
            Sniffer.stopButton.setEnabled(true);
            Sniffer.exportButton.setEnabled(true);
        } else {
            String errorMessage = "Select an Interface between 0 and " + (COUNTER - 1) + "!";
            JOptionPane.showMessageDialog(null, errorMessage);
            new NetworkInterfaces();
        }

        selectionTextField.setText("");

    }

    public static void main(String[] args) {

        try {
            for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            Logger.getLogger(NetworkInterfaces.class.getName()).log(Level.SEVERE, null, ex);
        }

        /* Create and display the form */
        Runnable newRun = NetworkInterfaces::new;
        EventQueue.invokeLater(newRun);
    }

    private TextField selectionTextField;

    // Generated using JFormDesigner Evaluation license - unknown
    private void initComponents() {
        JScrollPane mainPane = new JScrollPane();
        //    @SuppressWarnings("unchecked")
        // Generated using JFormDesigner Evaluation license - unknown
        JTextArea interfacesTextArea = new JTextArea();
        JButton selectButton = new JButton();
        selectionTextField = new TextField();
        JLabel messageLabel = new JLabel();
        JEditorPane interfacesPane = new JEditorPane("text/html", interfacesData);

        interfacesPane.setEditable(false);
        setVisible(true);

        //======== this ========
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setTitle("Interfaces List");
        setName("Interfaces list");
        var contentPane = getContentPane();

        //======== mainPane ========
        {

            //---- interfacesTextArea ----
            interfacesTextArea.setEditable(false);
            interfacesTextArea.setColumns(20);
            interfacesTextArea.setRows(5);
            interfacesPane.setCaretPosition(0);
            mainPane.setViewportView(interfacesPane);
        }

        //---- selectButton ----
        selectButton.setText("Select");
        selectButton.addActionListener(this::selectButtonAction);

        //---- selectionTextField ----
        selectionTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                selectTextFieldKeyPressed(e);
            }
        });

        //---- messageLabel ----
        messageLabel.setText("Please select an interface number");

        GroupLayout contentPaneLayout = new GroupLayout(contentPane);
        contentPane.setLayout(contentPaneLayout);
        contentPaneLayout.setHorizontalGroup(
                contentPaneLayout.createParallelGroup()
                        .addGroup(contentPaneLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(contentPaneLayout.createParallelGroup()
                                        .addGroup(contentPaneLayout.createSequentialGroup()
                                                .addGap(0, 249, Short.MAX_VALUE)
                                                .addComponent(messageLabel, GroupLayout.PREFERRED_SIZE, 220, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                                .addComponent(selectionTextField, GroupLayout.PREFERRED_SIZE, 60, GroupLayout.PREFERRED_SIZE)
                                                .addGap(47, 47, 47)
                                                .addComponent(selectButton, GroupLayout.PREFERRED_SIZE, 75, GroupLayout.PREFERRED_SIZE))
                                        .addComponent(mainPane))
                                .addContainerGap())
        );
        contentPaneLayout.setVerticalGroup(
                contentPaneLayout.createParallelGroup()
                        .addGroup(contentPaneLayout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(mainPane, GroupLayout.PREFERRED_SIZE, 352, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGroup(contentPaneLayout.createParallelGroup()
                                        .addComponent(selectionTextField, GroupLayout.Alignment.TRAILING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(selectButton, GroupLayout.Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 33, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(messageLabel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addContainerGap())
        );
        pack();
        setLocationRelativeTo(getOwner());
    }

    private void selectButtonAction(ActionEvent evt) {
        ChooseInterface();
        setVisible(false);
    }

    private void selectTextFieldKeyPressed(KeyEvent evt) {
        if (evt.getExtendedKeyCode() == KeyEvent.VK_ENTER) {
            ChooseInterface();
            setVisible(false);
        }
    }
}
