package windows;

import worker.IXssScannerWorkerMessageReceiver;
import worker.XssScannerWorker;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainWindow implements ActionListener, IXssScannerWorkerMessageReceiver{
    private final JFrame frame = new JFrame("XSS-Scanner");
    private final JLabel urlLabel = new JLabel("URL:");
    private final JTextField urlField = new JTextField("http://xss.cgaming.org/", 20);
    private final JLabel cookieNameLabel = new JLabel("Cookie Name:");
    private final JTextField cookieNameField = new JTextField("", 20);
    private final JLabel cookieValueLabel = new JLabel("Cookie Value:");
    private final JTextField cookieValueField = new JTextField("", 20);
    private final JTextArea logTextArea = new JTextArea(10, 50);
    private final JScrollPane logScrollPane = new JScrollPane(logTextArea);
    private final JButton startButton = new JButton("Start");
    private final JButton stopButton = new JButton("Stop");

    private ExecutorService executorService;

    private XssScannerWorker webCrawlerWorker;

    public MainWindow() {
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        initWindow(frame.getContentPane());
        frame.pack();
        frame.setVisible(true);
    }

    private void initWindow(Container container) {
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));

        initUrlControls(container);
        initOptionalControls(container);
        initLogControls(container);
        initSubmitControls(container);
    }

    private void initUrlControls(Container container) {
        JPanel urlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        urlField.setMaximumSize(urlField.getPreferredSize());

        urlPanel.add(urlLabel);
        urlPanel.add(urlField);

        container.add(urlPanel);
    }

    private void initOptionalControls(Container container) {
        JPanel cookieNamePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel cookieValuePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        cookieNamePanel.add(cookieNameLabel);
        cookieNamePanel.add(cookieNameField);

        cookieValuePanel.add(cookieValueLabel);
        cookieValuePanel.add(cookieValueField);

        container.add(cookieNamePanel);
        container.add(cookieValuePanel);
    }

    private void initLogControls(Container container) {
        logTextArea.setEditable(false);

        container.add(logScrollPane, BorderLayout.WEST);
    }

    private void initSubmitControls(Container container) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        startButton.addActionListener(this);
        stopButton.addActionListener(this);

        panel.add(startButton);
        panel.add(stopButton);

        container.add(panel);
    }

    private void addToLog(String message) {
        logTextArea.setText(logTextArea.getText() + message + System.lineSeparator());
    }

    private void setControlsEnabled(boolean enabled) {
        urlField.setEnabled(enabled);
        cookieNameField.setEnabled(enabled);
        cookieValueField.setEnabled(enabled);
        startButton.setEnabled(enabled);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == startButton) {
            onStartButtonClicked(e);
        }
        else if(e.getSource() == stopButton) {
            onStopButtonClicked(e);
        }
    }

    private void onStartButtonClicked(ActionEvent e) {

        executorService = Executors.newFixedThreadPool(3);

        setControlsEnabled(false);
        logTextArea.setText("");

        String url = urlField.getText();
        Map<String, String> cookies = getCookies();

        webCrawlerWorker = new XssScannerWorker(this, url, cookies);

        executorService.submit(webCrawlerWorker);
    }

    private Map<String, String> getCookies() {
        HashMap<String, String> cookies = new HashMap<String, String>();
        String cookieName = cookieNameField.getText();
        String cookieValue = cookieValueField.getText();

        if (!cookieName.isEmpty()) {
            cookies.put(cookieName, cookieValue);
        }

        return cookies;
    }

    private void onStopButtonClicked(ActionEvent e) {
        executorService.shutdownNow();
        setControlsEnabled(true);
    }

    @Override
    public void onXssScannerWorkerMessageReceived(String message) {
        addToLog(message);
    }

    @Override
    public void onXssScannerWorkerFinished(Set<URL> dUrls, Set<URL> iUrls) {
        addToLog(String.format("Script injection vulnerable urls: %d", dUrls.size()));
        if(dUrls.size() > 0) {
            for(URL url : dUrls) {
                addToLog(url.toString());
            }
        }
        addToLog(String.format("Image injection vulnerable urls: %d", iUrls.size()));
        if(iUrls.size() > 0) {
            for(URL url: iUrls) {
                addToLog(url.toString());
            }
        }

        setControlsEnabled(true);
    }
}