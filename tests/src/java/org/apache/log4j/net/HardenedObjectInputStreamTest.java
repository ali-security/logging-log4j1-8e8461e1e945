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
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Category;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LocationInfo;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.ThrowableInformation;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 *
 * Deeply nested hashmaps/hashtables declaring huge sizes also exhaust the
 * memory, as every level allocates its bucket table before reading its
 * content; the nesting depth and array length limits prevent that.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /** Element count claimed by every level of the crafted nested maps. */
    private static final int CLAIMED_SIZE = 8000000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (InvalidClassException e) {
            // Where the JVM supports serialization filters, the nesting
            // depth limit rejects it first with "filter status: REJECTED".
            // Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * CVE-2023-26464: deeply nested Hashtables, each declaring millions of
     * elements, make every level allocate a huge bucket table before its
     * content is read, until the receiver runs out of memory.
     */
    public void testNestedHashtablesDeclaringHugeSizesRejected() throws Exception {
        assertNestedMapsRejected(Hashtable.class);
    }

    /**
     * CVE-2023-26464: same attack with deeply nested HashMaps.
     */
    public void testNestedHashMapsDeclaringHugeSizesRejected() throws Exception {
        assertNestedMapsRejected(HashMap.class);
    }

    /**
     * Nested hash structures built from map entries rather than collections:
     * a single HashSet holding a DAG of map entries makes its hashCode()
     * exponential in the nesting depth.
     */
    public void testNestedMapEntriesRejected() throws Exception {
        Object entry = "leaf";
        for (int i = 0; i < 40; i++) {
            entry = new AbstractMap.SimpleEntry(entry, entry);
        }
        // add a cheap entry first, then hang the DAG below it so that
        // building the payload does not compute its hashCode()
        Map.Entry root = new AbstractMap.SimpleEntry("root", "value");
        Set set = new HashSet();
        set.add(root);
        root.setValue(entry);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(set)), new String[0]);
        try {
            Object outcome = readWithTimeout(hois, 30000);
            assertTrue("Nested map entries should be rejected, got " + outcome,
                    outcome instanceof InvalidObjectException || outcome instanceof InvalidClassException);
        } finally {
            hois.close();
        }
    }

    /**
     * More than MAX_COLLECTION_COUNT collections in one object graph are
     * rejected even when they are not nested.
     */
    public void testCollectionCountLimit() throws Exception {
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(listOfSets(HardenedObjectInputStream.MAX_COLLECTION_COUNT + 8))),
                new String[0]);
        try {
            hois.readObject();
            fail("More than " + HardenedObjectInputStream.MAX_COLLECTION_COUNT + " collections should be rejected");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit", e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * readAdaptedObject() gives every object read from the stream its own
     * collection budget, while readObject() keeps counting.
     */
    public void testReadAdaptedObjectResetsCollectionCount() throws Exception {
        int perObject = HardenedObjectInputStream.MAX_COLLECTION_COUNT / 2 + 4;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < 3; i++) {
            oos.writeObject(listOfSets(perObject));
            oos.reset();
        }
        oos.close();
        byte[] serialized = bos.toByteArray();

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialized), new String[0]);
        for (int i = 0; i < 3; i++) {
            List list = (List) hois.readAdaptedObject();
            assertEquals(perObject - 1, list.size());
        }
        hois.close();

        hois = new HardenedObjectInputStream(new ByteArrayInputStream(serialized), new String[0]);
        hois.readObject();
        try {
            hois.readObject();
            fail("readObject() should not reset the collection count");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit", e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * Logging events as sent by SocketAppender are still received.
     */
    public void testLoggingEventsAllowed() throws Exception {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        Hashtable properties = new Hashtable();
        properties.put("user", "alice");
        properties.put("session", "abc123");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < 3; i++) {
            LoggingEvent event = new LoggingEvent(Category.class.getName(), logger, System.currentTimeMillis(),
                    Level.ERROR, "message " + i, "main", new ThrowableInformation(new Exception("boom " + i)),
                    "ndc", new LocationInfo("Foo.java", "org.example.Foo", "bar", "42"), properties);
            oos.writeObject(event);
            oos.reset();
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        for (int i = 0; i < 3; i++) {
            LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
            assertEquals("message " + i, event.getRenderedMessage());
            assertEquals(Level.ERROR, event.getLevel());
            assertEquals("ndc", event.getNDC());
            assertEquals("alice", event.getMDC("user"));
            assertEquals("42", event.getLocationInformation().getLineNumber());
            assertTrue(event.getThrowableStrRep()[0].indexOf("boom " + i) >= 0);
        }
        hleis.close();
    }

    /**
     * A JVM-wide serialization filter stays in force next to the limits.
     */
    public void testJvmWideFilterStillApplied() throws Exception {
        Class configClass;
        try {
            configClass = Class.forName("java.io.ObjectInputFilter$Config");
        } catch (ClassNotFoundException e) {
            try {
                configClass = Class.forName("sun.misc.ObjectInputFilter$Config");
            } catch (ClassNotFoundException e2) {
                // JVM without serialization filters: nothing to preserve
                return;
            }
        }
        Object filter = configClass.getMethod("createFilter", new Class[] { String.class })
                .invoke(null, new Object[] { "!java.util.Vector" });
        Method getSerialFilter = configClass.getMethod("getSerialFilter", new Class[0]);
        Method setSerialFilter = null;
        Method[] methods = configClass.getMethods();
        for (int i = 0; i < methods.length; i++) {
            if ("setSerialFilter".equals(methods[i].getName())) {
                setSerialFilter = methods[i];
            }
        }
        assertNull("no JVM-wide filter expected in the test JVM", getSerialFilter.invoke(null, new Object[0]));
        setSerialFilter.invoke(null, new Object[] { filter });

        Vector vector = new Vector();
        vector.add("item");
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(vector)), new String[0]);
        try {
            hois.readObject();
            fail("The JVM-wide filter rejecting java.util.Vector should still apply");
        } catch (InvalidClassException e) {
            // rejected by the JVM-wide filter
        } finally {
            hois.close();
        }

        assertNestedMapsRejected(Hashtable.class);
        testModerateCollectionsAllowed();
    }

    private static List listOfSets(int collections) {
        List list = new ArrayList();
        for (int i = 1; i < collections; i++) {
            Set set = new HashSet();
            set.add("item" + i);
            list.add(set);
        }
        return list;
    }

    private void assertNestedMapsRejected(Class mapClass) throws Exception {
        // with each level allocating at least CLAIMED_SIZE references, nest
        // deep enough to exhaust the heap when the levels are not limited
        long perLevel = (long) CLAIMED_SIZE * 4;
        int levels = (int) Math.min(1000, Runtime.getRuntime().maxMemory() / perLevel + 2);
        byte[] payload = nestedMapsClaiming(mapClass, levels, CLAIMED_SIZE);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(new ByteArrayInputStream(payload),
                new String[0]);
        try {
            hois.readObject();
            fail("Nested maps declaring huge sizes should be rejected");
        } catch (InvalidClassException e) {
            // rejected by the nesting depth or array length limit
        } catch (InvalidObjectException e) {
            // rejected by the collection count limit
        } catch (OutOfMemoryError e) {
            fail("Nested maps declaring huge sizes exhausted the memory: " + e);
        } finally {
            hois.close();
        }
    }

    /**
     * Serializes <code>levels</code> maps nested in one another, each holding
     * a single entry, then rewrites the element count every map writes
     * ahead of its entries to <code>claimedSize</code>.
     */
    private byte[] nestedMapsClaiming(Class mapClass, int levels, int claimedSize) throws Exception {
        Map map = (Map) mapClass.newInstance();
        map.put("k", "v");
        for (int i = 1; i < levels; i++) {
            Map outer = (Map) mapClass.newInstance();
            outer.put("k", map);
            map = outer;
        }
        byte[] bytes = serialize(map);

        // Hashtable and HashMap write a block "TC_BLOCKDATA 8 <table length> <count>"
        // right before their first key ("k" as TC_STRING or TC_REFERENCE)
        int patched = 0;
        for (int i = 0; i + 10 < bytes.length; i++) {
            if (bytes[i] == 0x77 && bytes[i + 1] == 8 && readInt(bytes, i + 6) == 1
                    && (bytes[i + 10] == 0x74 || bytes[i + 10] == 0x71)) {
                writeInt(bytes, i + 6, claimedSize);
                patched++;
                i += 9;
            }
        }
        assertEquals("every nested map should declare the claimed size", levels, patched);
        return bytes;
    }

    private static int readInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24) | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8) | (bytes[offset + 3] & 0xff);
    }

    private static void writeInt(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 24);
        bytes[offset + 1] = (byte) (value >>> 16);
        bytes[offset + 2] = (byte) (value >>> 8);
        bytes[offset + 3] = (byte) value;
    }

    /**
     * Reads one object on another thread and returns the object or the
     * throwable it ended with; fails when it is still running after
     * <code>millis</code>, i.e. the deserialization burns the CPU.
     */
    private Object readWithTimeout(final HardenedObjectInputStream hois, long millis) throws InterruptedException {
        final Object[] outcome = new Object[1];
        Thread reader = new Thread("CVE-2023-26464 reader") {
            public void run() {
                try {
                    outcome[0] = hois.readObject();
                } catch (Throwable t) {
                    outcome[0] = t;
                }
            }
        };
        reader.setDaemon(true);
        reader.start();
        reader.join(millis);
        if (reader.isAlive()) {
            fail("Deserialization still running after " + millis + " ms");
        }
        return outcome[0];
    }
}
