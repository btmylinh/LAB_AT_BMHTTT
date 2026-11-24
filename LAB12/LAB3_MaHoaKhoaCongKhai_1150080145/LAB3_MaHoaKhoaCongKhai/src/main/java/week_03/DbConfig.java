package week_03;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;

public final class DbConfig {
    private static String server;
    private static int port;
    private static String database;
    private static String user;
    private static char[] password;

    private DbConfig() {
    }

    public static synchronized void set(String newServer, int newPort, String newDatabase,
            String newUser, char[] newPassword) {
        if (newServer.isBlank() || newDatabase.isBlank() || newUser.isBlank()) {
            throw new IllegalArgumentException("Server, Database và User không được để trống.");
        }
        if (newPort < 1 || newPort > 65535) {
            throw new IllegalArgumentException("Port phải nằm trong khoảng 1 - 65535.");
        }
        server = newServer;
        port = newPort;
        database = newDatabase;
        user = newUser;
        password = newPassword.clone();
    }

    public static synchronized void clear() {
        server = null;
        password = null;
    }

    public static synchronized boolean isReady() {
        return server != null;
    }

    public static synchronized Connection open() throws SQLException {
        if (server == null) {
            throw new SQLException("Chưa cấu hình SQL Server. Hãy mở form Kết nối SQL Server và bấm Test Connection.");
        }
        String url = "jdbc:sqlserver://" + server + ":" + port
                + ";databaseName=" + database
                + ";encrypt=true;trustServerCertificate=true;loginTimeout=5";
        return DriverManager.getConnection(url, user, new String(password));
    }

    public static String test() throws SQLException {
        try (Connection con = open()) {
            DatabaseMetaData md = con.getMetaData();
            return "Kết nối thành công: " + md.getDatabaseProductName() + " "
                    + md.getDatabaseProductVersion() + " — database " + con.getCatalog();
        }
    }
}