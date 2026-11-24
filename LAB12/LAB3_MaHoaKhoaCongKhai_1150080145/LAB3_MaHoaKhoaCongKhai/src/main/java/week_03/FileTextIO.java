package week_03;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;

public final class FileTextIO {
    private FileTextIO() {
    }

    public static String openText(JFrame parent, JTextArea target) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("Text file (*.txt)", "txt"));
        if (chooser.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        File file = chooser.getSelectedFile();
        try {
            target.setText(Files.readString(file.toPath(), StandardCharsets.UTF_8).trim());
            return file.getAbsolutePath();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Không đọc được tệp: " + ex.getMessage(),
                    "Lỗi mở tệp", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    public static String saveText(JFrame parent, JTextArea source, String defaultName) {
        if (source.getText().isBlank()) {
            JOptionPane.showMessageDialog(parent, "Chưa có nội dung để lưu.");
            return null;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".txt")) {
            file = new File(file.getParentFile(), file.getName() + ".txt");
        }
        try {
            Files.writeString(file.toPath(), source.getText(), StandardCharsets.UTF_8);
            return file.getAbsolutePath();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Không lưu được tệp: " + ex.getMessage(),
                    "Lỗi lưu tệp", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    public static String openString(JFrame parent) {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("Text file (*.txt)", "txt"));
        if (chooser.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        try {
            return Files.readString(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Không đọc được tệp: " + ex.getMessage(),
                    "Lỗi mở tệp", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    public static String saveString(JFrame parent, String content, String defaultName) {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".txt")) {
            file = new File(file.getParentFile(), file.getName() + ".txt");
        }
        try {
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return file.getAbsolutePath();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Không lưu được tệp: " + ex.getMessage(),
                    "Lỗi lưu tệp", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
}