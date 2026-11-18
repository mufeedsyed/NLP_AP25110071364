package cyberthreatintel;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

class ThreatReport {
    private final String text;
    private final String source;

    public ThreatReport(String text) {
        this(text, "Manual Input");
    }

    public ThreatReport(String text, String source) {
        this.text = text;
        this.source = source;
    }

    public String getText() {
        return text;
    }

    public String getSource() {
        return source;
    }
}

class TextPreprocessor {
    private static final Set<String> STOP_WORDS = new HashSet<>(
        Arrays.asList(
            "the", "is", "a", "an", "and", "or", "of", "to",
            "in", "on", "for", "with", "by", "was", "were",
            "are", "be", "has", "have", "had", "this", "that",
            "from", "it", "as", "at", "their", "they"
        )
    );

    public String[] preprocess(String text) {
        if (text == null || text.trim().isEmpty()) {
            return new String[0];
        }

        String cleaned = text.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9\\s]", " ")
                .trim();

        if (cleaned.isEmpty()) {
            return new String[0];
        }

        return Arrays.stream(cleaned.split("\\s+"))
                .filter(word -> !STOP_WORDS.contains(word))
                .toArray(String[]::new);
    }
}

class NaiveBayesClassifier extends TextPreprocessor {
    private final Map<String, Map<String, Integer>> wordCounts;
    private final Map<String, Integer> categoryWordTotals;
    private final Map<String, Integer> documentCounts;
    private final Set<String> vocabulary;
    private int totalDocuments;

    public NaiveBayesClassifier() {
        wordCounts = new HashMap<>();
        categoryWordTotals = new HashMap<>();
        documentCounts = new HashMap<>();
        vocabulary = new HashSet<>();

        train("Ransomware",
            "ransomware encrypt encrypted encryption files ransom payment "
            + "victim locked restore decrypt extortion");

        train("Phishing",
            "phishing email emails password credentials fraudulent "
            + "malicious link fake login impersonation scam");

        train("Malware",
            "malware trojan virus spyware infection malicious software "
            + "payload executable backdoor");

        train("Data Breach",
            "data breach stolen leaked database information exposed "
            + "records exfiltration confidential");

        train("Denial of Service",
            "denial service ddos dos traffic server network overload "
            + "requests unavailable flooding");

        train("Credential Theft",
            "credential theft stolen username password authentication "
            + "account login keylogger identity");

        train("Ransomware",
            "attackers encrypted documents demanded cryptocurrency "
            + "payment files inaccessible");

        train("Phishing",
            "fraudulent message directed employees to fake website "
            + "steal credentials");
    }

    private void train(String category, String text) {
        String[] words = preprocess(text);

        wordCounts.putIfAbsent(category, new HashMap<>());

        documentCounts.put(
            category, documentCounts.getOrDefault(category, 0) + 1
        );

        totalDocuments++;

        Map<String, Integer> counts = wordCounts.get(category);

        for (String word : words) {
            counts.put(word, counts.getOrDefault(word, 0) + 1);

            categoryWordTotals.put(
                category, categoryWordTotals.getOrDefault(category, 0) + 1
            );

            vocabulary.add(word);
        }
    }

    public String classify(String text) throws Exception {
        String[] words = preprocess(text);

        if (words.length == 0) {
            throw new Exception("Please enter a valid cyber threat report.");
        }

        String bestCategory = "Unknown";
        double bestScore = Double.NEGATIVE_INFINITY;

        for (String category : wordCounts.keySet()) {

            double prior = Math.log(
                (double) documentCounts.get(category) / totalDocuments
            );

            double score = prior;

            Map<String, Integer> counts = wordCounts.get(category);

            int totalWords = categoryWordTotals.get(category);

            for (String word : words) {
                int count = counts.getOrDefault(word, 0);

                double probability =
                    (count + 1.0) / (totalWords + vocabulary.size());

                score += Math.log(probability);
            }

            if (score > bestScore) {
                bestScore = score;
                bestCategory = category;
            }
        }

        return bestCategory;
    }

    public String[] getKeywords(String text) {
        String[] words = preprocess(text);

        LinkedHashSet<String> keywords = new LinkedHashSet<>();

        for (String word : words) {
            if (vocabulary.contains(word)) {
                keywords.add(word);
            }

            if (keywords.size() == 8) {
                break;
            }
        }

        if (keywords.isEmpty()) {
            return new String[]{"No known keywords found"};
        }

        return keywords.toArray(new String[0]);
    }
}

class ClassificationResult {
    private final String category;
    private final String[] keywords;
    private final String timestamp;
    private final String source;

    public ClassificationResult(
            String category, String[] keywords, String source) {

        this.category = category;
        this.keywords = keywords;
        this.source = source;

        timestamp = LocalDateTime.now().format(
            DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss")
        );
    }

    public String getCategory() {
        return category;
    }

    public String[] getKeywords() {
        return keywords;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getSource() {
        return source;
    }
}

class ReportAnalyzer extends NaiveBayesClassifier {

    public ClassificationResult analyze(ThreatReport report)
            throws Exception {

        if (report == null) {
            throw new Exception("Report cannot be null.");
        }

        return analyze(report.getText(), report.getSource());
    }

    public ClassificationResult analyze(String text, String source)
            throws Exception {

        String category = classify(text);

        String[] keywords = getKeywords(text);

        return new ClassificationResult(category, keywords, source);
    }
}

class HistoryManager {
    private final DefaultTableModel model;

    public HistoryManager(DefaultTableModel model) {
        this.model = model;
    }

    public void addResult(ClassificationResult result) {

        model.addRow(new Object[]{
            result.getTimestamp(),
            result.getSource(),
            result.getCategory(),
            String.join(", ", result.getKeywords())
        });
    }

    public void exportHistory(Component parent) {

        JFileChooser chooser = new JFileChooser();

        chooser.setSelectedFile(new File("classification_history.csv"));

        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();

        try (PrintWriter writer = new PrintWriter(new FileWriter(file))) {

            writer.println("Date and Time,Source,Category,Keywords");

            for (int i = 0; i < model.getRowCount(); i++) {

                writer.println(
                    csv(model.getValueAt(i, 0)) + "," +
                    csv(model.getValueAt(i, 1)) + "," +
                    csv(model.getValueAt(i, 2)) + "," +
                    csv(model.getValueAt(i, 3))
                );
            }

            JOptionPane.showMessageDialog(
                parent, "History exported successfully."
            );

        } catch (IOException ex) {

            JOptionPane.showMessageDialog(
                parent,
                "Unable to export history: " + ex.getMessage(),
                "File Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private String csv(Object value) {
        String text = String.valueOf(value);
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }
}

class CyberThreatDashboard extends JFrame {

    private final JTextArea reportArea;
    private final JTextArea resultArea;
    private final JLabel statusLabel;
    private final JButton analyzeButton;

    private final ReportAnalyzer analyzer;
    private final HistoryManager historyManager;
    private final DefaultTableModel historyModel;

    private String currentSource = "Manual Input";

    public CyberThreatDashboard() {

        analyzer = new ReportAnalyzer();

        setTitle("CyberThreat Intel | Threat Report Classifier");

        setSize(1050, 720);

        setMinimumSize(new Dimension(850, 600));

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setLocationRelativeTo(null);

        Color background = new Color(19, 27, 43);
        Color panelColor = new Color(30, 41, 59);
        Color accent = new Color(56, 189, 248);
        Color foreground = new Color(235, 241, 250);

        JPanel root = new JPanel(new BorderLayout(12, 12));

        root.setBackground(background);

        root.setBorder(
            BorderFactory.createEmptyBorder(18, 18, 18, 18)
        );

        JLabel heading = new JLabel(
            "CyberThreat Intel", SwingConstants.CENTER
        );

        heading.setForeground(accent);

        heading.setFont(new Font("Arial", Font.BOLD, 28));

        JLabel subtitle = new JLabel(
            "NLP-Based Classification of Cyber Threat Intelligence Reports",
            SwingConstants.CENTER
        );

        subtitle.setForeground(foreground);

        subtitle.setFont(new Font("Arial", Font.PLAIN, 13));

        JPanel header = new JPanel(new GridLayout(2, 1, 4, 4));

        header.setBackground(background);

        header.add(heading);
        header.add(subtitle);

        root.add(header, BorderLayout.NORTH);

        reportArea = new JTextArea(10, 50);

        reportArea.setLineWrap(true);

        reportArea.setWrapStyleWord(true);

        reportArea.setFont(new Font("Consolas", Font.PLAIN, 14));

        reportArea.setBackground(panelColor);

        reportArea.setForeground(foreground);

        reportArea.setCaretColor(accent);

        reportArea.setBorder(
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        );

        JScrollPane inputScroll = new JScrollPane(reportArea);

        inputScroll.setBorder(
            BorderFactory.createTitledBorder("Threat Report Input")
        );

        resultArea = new JTextArea(5, 50);

        resultArea.setEditable(false);

        resultArea.setLineWrap(true);

        resultArea.setWrapStyleWord(true);

        resultArea.setFont(new Font("Consolas", Font.PLAIN, 14));

        resultArea.setBackground(panelColor);

        resultArea.setForeground(foreground);

        resultArea.setBorder(
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        );

        JScrollPane resultScroll = new JScrollPane(resultArea);

        resultScroll.setBorder(
            BorderFactory.createTitledBorder("Analysis Results")
        );

        JButton loadButton = new JButton("Load Report");

        analyzeButton = new JButton("Analyze Report");

        JButton clearButton = new JButton("Clear");

        JButton exportButton = new JButton("Export History");

        loadButton.setToolTipText("Open a text report file");

        analyzeButton.setToolTipText("Classify the report");

        clearButton.setToolTipText("Clear the input and results");

        JPanel buttons = new JPanel(
            new FlowLayout(FlowLayout.CENTER, 12, 10)
        );

        buttons.setBackground(background);

        buttons.add(loadButton);
        buttons.add(analyzeButton);
        buttons.add(clearButton);
        buttons.add(exportButton);

        JPanel workPanel = new JPanel(new BorderLayout(10, 10));

        workPanel.setBackground(background);

        workPanel.add(inputScroll, BorderLayout.CENTER);

        workPanel.add(buttons, BorderLayout.SOUTH);

        historyModel = new DefaultTableModel(
            new String[]{"Date and Time", "Source", "Category", "Keywords"}, 0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable historyTable = new JTable(historyModel);

        historyTable.setRowHeight(24);

        historyTable.setAutoResizeMode(
            JTable.AUTO_RESIZE_ALL_COLUMNS
        );

        JScrollPane historyScroll = new JScrollPane(historyTable);

        historyScroll.setBorder(
            BorderFactory.createTitledBorder("Session History")
        );

        historyManager = new HistoryManager(historyModel);

        JTabbedPane tabs = new JTabbedPane();

        tabs.addTab("Analyze", workPanel);

        tabs.addTab("History", historyScroll);

        statusLabel = new JLabel("Ready");

        statusLabel.setForeground(accent);

        JPanel bottom = new JPanel(new BorderLayout(10, 10));

        bottom.setBackground(background);

        bottom.add(resultScroll, BorderLayout.CENTER);

        bottom.add(statusLabel, BorderLayout.SOUTH);

        JPanel center = new JPanel(new BorderLayout(10, 10));

        center.setBackground(background);

        center.add(tabs, BorderLayout.CENTER);

        center.add(bottom, BorderLayout.SOUTH);

        root.add(center, BorderLayout.CENTER);

        add(root);

        loadButton.addActionListener(e -> loadReport());

        analyzeButton.addActionListener(e -> analyzeReport());

        clearButton.addActionListener(e -> {

            reportArea.setText("");

            resultArea.setText("");

            currentSource = "Manual Input";

            statusLabel.setText("Ready");
        });

        exportButton.addActionListener(
            e -> historyManager.exportHistory(this)
        );
    }

    private void loadReport() {

        JFileChooser chooser = new JFileChooser();

        chooser.setDialogTitle("Select Cyber Threat Report");

        int choice = chooser.showOpenDialog(this);

        if (choice == JFileChooser.APPROVE_OPTION) {

            File file = chooser.getSelectedFile();

            if (!file.getName().toLowerCase(Locale.ROOT).endsWith(".txt")) {

                JOptionPane.showMessageDialog(
                    this, "Please select a .txt file.",
                    "Invalid File", JOptionPane.WARNING_MESSAGE
                );

                return;
            }

            try (BufferedReader reader = new BufferedReader(
                    new FileReader(file))) {

                StringBuilder content = new StringBuilder();

                String line;

                while ((line = reader.readLine()) != null) {

                    content.append(line).append("\n");
                }

                reportArea.setText(content.toString());

                currentSource = file.getName();

                statusLabel.setText("Report loaded successfully.");

            } catch (IOException ex) {

                JOptionPane.showMessageDialog(
                    this, "Unable to read report: " + ex.getMessage(),
                    "File Error", JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private void analyzeReport() {

        String text = reportArea.getText();

        String source = currentSource;

        analyzeButton.setEnabled(false);

        resultArea.setText("Analyzing report...");

        statusLabel.setText("Processing in background...");

        SwingWorker<ClassificationResult, Void> worker =
            new SwingWorker<ClassificationResult, Void>() {

            @Override
            protected ClassificationResult doInBackground()
                    throws Exception {

                ThreatReport report = new ThreatReport(text, source);

                return analyzer.analyze(report);
            }

            @Override
            protected void done() {

                try {

                    ClassificationResult result = get();

                    resultArea.setText(
                        "Predicted Threat Category: " + result.getCategory()
                        + "\n\nImportant Keywords: "
                        + String.join(", ", result.getKeywords())
                        + "\n\nSource: " + result.getSource()
                        + "\nAnalyzed At: " + result.getTimestamp()
                        + "\n\nNote: Prototype prediction; not a validated "
                        + "security assessment."
                    );

                    historyManager.addResult(result);

                    statusLabel.setText("Classification completed.");

                } catch (InterruptedException ex) {

                    Thread.currentThread().interrupt();

                    statusLabel.setText("Analysis interrupted.");

                } catch (ExecutionException ex) {

                    Throwable cause = ex.getCause();

                    String message = cause == null
                        ? "Unable to analyze the report."
                        : cause.getMessage();

                    resultArea.setText(message);

                    statusLabel.setText("Classification failed.");

                } finally {

                    analyzeButton.setEnabled(true);
                }
            }
        };

        worker.execute();
    }
}

public class Main {
    public static void main(String[] args) {
        ApplicationHost.bootstrapSystem(args);
    }

    private static class ApplicationHost {
        public static void bootstrapSystem(String[] cliArgs) {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ex) {
                System.out.println("Notice: Operating system theme unavailable, using standard layout.");
            }

            EventQueue.invokeLater(new DispatchWorker());
        }
    }

    private static final class DispatchWorker implements Runnable {
        @Override
        public void run() {
            CyberThreatDashboard instance = new CyberThreatDashboard();
            instance.setVisible(true);
        }
    }
}