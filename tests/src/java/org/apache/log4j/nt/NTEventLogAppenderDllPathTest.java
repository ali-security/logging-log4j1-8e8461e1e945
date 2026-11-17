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

package org.apache.log4j.nt;

import java.io.File;
import java.io.IOException;

import junit.framework.TestCase;
import org.apache.log4j.LogManager;


/**
 * NTEventLogAppender DLL path resolution tests
 * (log4j.nteventlog.dll.path, DLL preloading mitigation).
 */
public class NTEventLogAppenderDllPathTest extends TestCase {

  private String originalDllPath;

  public void setUp() {
    originalDllPath = System.getProperty(NTEventLogAppender.DLL_PATH_PROPERTY);
    clearDllPathProperty();
  }

  public void tearDown() {
    if (originalDllPath != null) {
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, originalDllPath);
    } else {
      clearDllPathProperty();
    }
    LogManager.shutdown();
  }

  /**
   * Removes the DLL path system property
   * (equivalent of System.clearProperty, which requires JDK 1.5).
   */
  private static void clearDllPathProperty() {
    System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
  }

  /**
   * When the system property is not set, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_notSet() {
    clearDllPathProperty();
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an empty string, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_emptyString() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is whitespace only, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_whitespaceOnly() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "   ");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is a relative path, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_relativePath() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "relative/path/NTEventLogAppender.dll");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an absolute path to a file that does not exist,
   * resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_absoluteButMissing() {
    String missingPath = new File(System.getProperty("java.io.tmpdir"), "no_such_NTEventLogAppender.dll")
        .getAbsolutePath();
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, missingPath);
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an absolute path to an existing file,
   * resolveConfiguredDllPath should return that absolute path.
   */
  public void testResolveConfiguredDllPath_absoluteAndExists() throws IOException {
    File tempFile = File.createTempFile("NTEventLogAppender", ".dll");
    tempFile.deleteOnExit();
    try {
      String absolutePath = tempFile.getAbsolutePath();
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, absolutePath);
      String result = NTEventLogAppender.resolveConfiguredDllPath();
      assertNotNull(result);
      assertEquals(absolutePath, result);
    } finally {
      tempFile.delete();
    }
  }
}
