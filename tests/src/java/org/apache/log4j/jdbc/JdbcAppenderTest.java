/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.jdbc;

import junit.framework.TestCase;

import org.apache.log4j.Appender;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Tests for {@link JDBCAppender}, including CVE-2022-23305 SQL injection regression tests.
 */
public class JdbcAppenderTest extends TestCase {
    private static final String SECURE_JDBC_REPLACEMENT =
            "org.apache.log4j.jdbc.JDBCAppender.secure_jdbc_replacement";

    /**
     * Closes the string literal of the column it is formatted into, terminates the
     * VALUES row, appends a forged row and comments out the rest of the statement.
     */
    private static final String INJECTION_PAYLOAD = "x','y'),('FORGED','f','f','f')--";

    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    public JdbcAppenderTest(final String name) {
        super(name);
    }

    public void setUp() throws Exception {
        Class.forName("org.h2.Driver");
        con = DriverManager.getConnection("jdbc:h2:mem:test_db");
        Statement st = con.createStatement();
        try {
            st.execute("create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
        } finally {
            st.close();
        }
    }

    public void tearDown() throws SQLException {
        LogManager.shutdown();
        con.close();
    }

    public void testJdbcInsecure() throws SQLException {
        System.setProperty(SECURE_JDBC_REPLACEMENT, "false");
        try {
            PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
            Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
            // Keep errors
            VectorErrorHandler errorHandler = new VectorErrorHandler();
            jdbcAppender.setErrorHandler(errorHandler);

            Logger logger = Logger.getLogger(JdbcAppenderTest.class);

            String oldThreadName = Thread.currentThread().getName();
            try {
                Thread.currentThread().setName("main");
                logger.debug("message with '' quote");
                assertEquals(
                        "batchSize=1, so messages should be added immediately",
                        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                        joinSorted(getMessages()));

                // It should fail
                logger.fatal("message with ' quote");

                assertEquals(
                        "Inserting a message with ' should cause failure in insecure mode, so only one message should be in the DB",
                        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                        joinSorted(getMessages()));

                StringBuffer exceptions = new StringBuffer();
                StringBuffer errorCodes = new StringBuffer();
                for (int i = 0; i < errorHandler.size(); i++) {
                    Exception ex = errorHandler.getException(i);
                    exceptions.append(ex.toString());
                    errorCodes.append(
                            ex instanceof SQLException
                                    ? ("SQLException.getErrorCode() = " + ((SQLException) ex).getErrorCode())
                                    : ("SQL Exception expected, got " + ex.getClass()));
                    exceptions.append('\n');
                    errorCodes.append('\n');
                }
                assertEquals(
                        "Logging a message with ' should trigger SQLException 'Syntax error in SQL statement...' when using insecure JDBCAppender mode, actual exceptions are\n" + exceptions,
                        "SQLException.getErrorCode() = 42001\n",
                        errorCodes.toString()
                );
            } finally {
                Thread.currentThread().setName(oldThreadName);
            }
        } finally {
            System.getProperties().remove(SECURE_JDBC_REPLACEMENT);
        }
    }

    public void testJdbcBufferSize1() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

        Logger logger = Logger.getLogger(JdbcAppenderTest.class);

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.debug("message with ' quote");
            assertEquals(
                    "batchSize=1, so messages should be added immediately",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                    joinSorted(getMessages()));

            logger.fatal("message with \" quote");

            assertEquals(
                    "batchSize=1, so two messages should be in DB after two logging calls",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
                    joinSorted(getMessages()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    public void testJdbcBufferSize2() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

        Logger logger = Logger.getLogger(JdbcAppenderTest.class);

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.log(XLevel.TRACE, "xtrace message");
            logger.debug("message with ' quote");
            logger.info("message with \" quote");
            logger.warn("?");
            // bufferSize=2, so this messsage won't yet be stored to the db
            logger.error("m4");

            assertEquals(
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
                            "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
                            "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessages()));

            logger.fatal("m5");

            assertEquals(
                    "Logging m5 message should trigger buffer flush for both m4 and m5",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n" +
                            "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n" +
                            "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
                            "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
                            "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessages()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    /**
     * Shows that INJECTION_PAYLOAD is a working exploit against the former
     * statement building: with the secure replacement disabled, the logged
     * message rewrites the INSERT and a forged row is stored.
     */
    public void testSqlInjectionViaMessageInInsecureMode() throws SQLException {
        System.setProperty(SECURE_JDBC_REPLACEMENT, "false");
        try {
            PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
            VectorErrorHandler errorHandler = new VectorErrorHandler();
            LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

            Logger.getLogger(JdbcAppenderTest.class).fatal(INJECTION_PAYLOAD);

            assertEquals(
                    "insecure mode formats the message into the SQL text, so the payload injects a forged row; errors: "
                            + errorHandler.size() + (errorHandler.size() > 0 ? " " + errorHandler.getException(0) : ""),
                    "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; x; y\n" +
                            "FORGED; f; f; f\n",
                    joinSorted(getMessages()));
        } finally {
            System.getProperties().remove(SECURE_JDBC_REPLACEMENT);
        }
    }

    /**
     * CVE-2022-23305: a crafted message (%m) must be stored verbatim and must not alter the SQL.
     */
    public void testSqlInjectionViaMessageIsPrevented() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

        Logger.getLogger(JdbcAppenderTest.class).fatal(INJECTION_PAYLOAD);

        assertNoErrors(errorHandler);
        assertEquals(
                "the message must be bound as a parameter, so exactly one row holding the payload is stored",
                "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; " + INJECTION_PAYLOAD
                        + ";  org.apache.log4j.jdbc.JdbcAppenderTest FATAL " + INJECTION_PAYLOAD + "\n",
                joinSorted(getMessages()));
    }

    /**
     * CVE-2022-23305: a crafted logger name (%c) must be stored verbatim and must not alter the SQL.
     */
    public void testSqlInjectionViaLoggerNameIsPrevented() throws SQLException {
        PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

        Logger.getLogger(INJECTION_PAYLOAD).warn("m");

        assertNoErrors(errorHandler);
        assertEquals(
                "the logger name must be bound as a parameter, so exactly one row holding the payload is stored",
                "WARN; " + INJECTION_PAYLOAD + "; m;  " + INJECTION_PAYLOAD + " WARN m\n",
                joinSorted(getMessages()));
    }

    /**
     * CVE-2022-23305: crafted MDC (%X), NDC (%x) and thread name (%t) values, with an
     * appender configured programmatically, must be stored verbatim and must not alter the SQL.
     */
    public void testSqlInjectionViaMdcNdcAndThreadNameIsPrevented() throws SQLException {
        JDBCAppender appender = new JDBCAppender();
        appender.setURL("jdbc:h2:mem:test_db");
        appender.setUser("");
        appender.setPassword("");
        appender.setSql("insert into logs(level,location,message,message2) values('%X{user}','%x','%t', 'thread=%t')");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        appender.setErrorHandler(errorHandler);

        Logger logger = Logger.getLogger("org.apache.log4j.jdbc.injection");
        logger.setAdditivity(false);
        logger.addAppender(appender);

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName(INJECTION_PAYLOAD);
            MDC.put("user", INJECTION_PAYLOAD);
            NDC.push(INJECTION_PAYLOAD);
            logger.error("m");
        } finally {
            NDC.remove();
            MDC.remove("user");
            Thread.currentThread().setName(oldThreadName);
        }

        assertNoErrors(errorHandler);
        assertEquals(
                "MDC, NDC and thread name must be bound as parameters, so exactly one row holding the payloads is stored",
                INJECTION_PAYLOAD + "; " + INJECTION_PAYLOAD + "; " + INJECTION_PAYLOAD
                        + "; thread=" + INJECTION_PAYLOAD + "\n",
                joinSorted(getMessages()));
    }

    private static void assertNoErrors(VectorErrorHandler errorHandler) {
        StringBuffer exceptions = new StringBuffer();
        for (int i = 0; i < errorHandler.size(); i++) {
            exceptions.append(errorHandler.getMessage(i)).append(": ")
                    .append(errorHandler.getException(i)).append('\n');
        }
        assertEquals("JDBCAppender reported errors:\n" + exceptions, 0, errorHandler.size());
    }

    private static String joinSorted(List list) {
        Collections.sort(list);
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < list.size(); i++) {
            sb.append((String) list.get(i)).append('\n');
        }
        return sb.toString();
    }

    private List getMessages() throws SQLException {
        List res = new ArrayList();
        PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
        try {
            ResultSet rs = ps.executeQuery();
            try {
                while (rs.next()) {
                    res.add(rs.getString(1) + "; " + rs.getString(2)
                            + "; " + rs.getString(3) + "; " + rs.getString(4));
                }
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
        return res;
    }
}
