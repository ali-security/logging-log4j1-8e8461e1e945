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

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.log4j.helpers.LogLog;

/**
 * HardenedObjectInputStream restricts the set of classes that can be
 * deserialized to a set of explicitly whitelisted classes. This prevents
 * certain type of attacks from being successful.
 * 
 * <p>
 * It is assumed that classes in the "java.lang" and "java.util" packages are
 * always authorized.
 * </p>
 * 
 * @author Ceki G&uuml;lc&uuml;
 * @since 1.2.18
 * 
 *        === Copied from the logback project with permission ==
 */
public class HardenedObjectInputStream extends ObjectInputStream {

	static final String ARRAY_CLASS_PREFIX = "[L";
	final List whitelistedClassNames;
	final static String[] JAVA_PACKAGES = new String[] { "java.lang", "java.util", ARRAY_CLASS_PREFIX + "java.lang" };

	/**
	 * Maximum number of Map/Collection instances allowed during deserialization
	 * of a single object graph. This mitigates CVE-2023-26464 where deeply
	 * nested hash-based collections cause exponential hashCode() computation.
	 *
	 * With N collection objects, the worst-case hashCode cost is O(2^(N/2)).
	 * A limit of 32 bounds this to O(2^16) = ~65K operations.
	 * A normal LoggingEvent has 1-2 collections (MDC Hashtable, properties).
	 */
	static final int MAX_COLLECTION_COUNT = 32;

	/**
	 * Maximum nesting depth of the deserialized object graph. Mitigates
	 * CVE-2023-26464: every level of a deeply nested hashmap/hashtable
	 * allocates its bucket table before any of its content is read.
	 * A normal LoggingEvent graph is at most 4 levels deep.
	 */
	static final int MAX_DEPTH = 16;

	/**
	 * Maximum length of any array, including the bucket tables that
	 * hashmaps/hashtables size from a count read off the stream, so that
	 * a few bytes cannot make the receiver allocate huge tables
	 * (CVE-2023-26464).
	 */
	static final int MAX_ARRAY_LENGTH = 10000;

	static final String LIMITS_FILTER_PATTERN = "maxdepth=" + MAX_DEPTH + ";maxarray=" + MAX_ARRAY_LENGTH;

	private int collectionCount = 0;

	public HardenedObjectInputStream(InputStream in, String[] whilelist) throws IOException {
		super(in);
		enableResolveObject(true);
		installLimitsFilter();

		this.whitelistedClassNames = new ArrayList();
		if (whilelist != null) {
			for (int i = 0; i < whilelist.length; i++) {
				this.whitelistedClassNames.add(whilelist[i]);
			}
		}
	}

	public HardenedObjectInputStream(InputStream in, List whitelist) throws IOException {
		super(in);
		enableResolveObject(true);
		installLimitsFilter();

		this.whitelistedClassNames = new ArrayList();
		this.whitelistedClassNames.addAll(whitelist);
	}

	protected Class resolveClass(ObjectStreamClass anObjectStreamClass) throws IOException, ClassNotFoundException {

		String incomingClassName = anObjectStreamClass.getName();

		if (!isWhitelisted(incomingClassName)) {
			throw new InvalidClassException("Unauthorized deserialization attempt", incomingClassName);
		}

		return super.resolveClass(anObjectStreamClass);
	}

	private boolean isWhitelisted(String incomingClassName) {
		for (int i = 0; i < JAVA_PACKAGES.length; i++) {
			if (incomingClassName.startsWith(JAVA_PACKAGES[i]))
				return true;
		}
		for (int i = 0; i < whitelistedClassNames.size(); i++) {
			String whiteListed = (String) whitelistedClassNames.get(i);
			if (incomingClassName.equals(whiteListed))
				return true;
		}
		return false;
	}

	/**
	 * Reads an object from the stream, resetting the collection counter
	 * so that each top-level readObject call gets its own budget.
	 * Callers should use this instead of {@link #readObject()} directly
	 * when reading multiple objects from the same stream.
	 */
	public Object readAdaptedObject() throws IOException, ClassNotFoundException {
		collectionCount = 0;
		return readObject();
	}

	/**
	 * Counts Map and Collection instances during deserialization to prevent
	 * CVE-2023-26464: deeply nested hash-based collections cause exponential
	 * hashCode() computation during deserialization. Map entries are counted
	 * as well since their hashCode() also recurses into their key and value.
	 */
	protected Object resolveObject(Object obj) throws IOException {
		if (obj instanceof Map || obj instanceof Collection || obj instanceof Map.Entry) {
			collectionCount++;
			if (collectionCount > MAX_COLLECTION_COUNT) {
				throw new InvalidObjectException(
					"Exceeded maximum number of collection objects during deserialization: "
					+ MAX_COLLECTION_COUNT
					+ ". Possible CVE-2023-26464 attack via nested collections.");
			}
		}
		return super.resolveObject(obj);
	}

	/**
	 * Enforces {@link #MAX_DEPTH} and {@link #MAX_ARRAY_LENGTH} through the
	 * JVM serialization filter (JEP 290: Java 9+, 8u121+, 7u131+, 6u141+),
	 * chained in front of any filter already set on this stream such as the
	 * JVM-wide jdk.serialFilter. This is what stops the CVE-2023-26464
	 * memory exhaustion, as the tables are allocated before
	 * {@link #resolveObject(Object)} sees anything. Accessed reflectively so
	 * that log4j keeps running on JVMs without serialization filters, where
	 * only the collection count limit applies.
	 */
	private void installLimitsFilter() {
		try {
			Class filterClass;
			Class configClass;
			Method getFilter;
			Method setFilter;
			boolean streamMethods;
			try {
				filterClass = Class.forName("java.io.ObjectInputFilter");
				configClass = Class.forName("java.io.ObjectInputFilter$Config");
				getFilter = ObjectInputStream.class.getMethod("getObjectInputFilter", new Class[0]);
				setFilter = ObjectInputStream.class.getMethod("setObjectInputFilter", new Class[] { filterClass });
				streamMethods = true;
			} catch (ClassNotFoundException e) {
				filterClass = Class.forName("sun.misc.ObjectInputFilter");
				configClass = Class.forName("sun.misc.ObjectInputFilter$Config");
				getFilter = configClass.getMethod("getObjectInputFilter", new Class[] { ObjectInputStream.class });
				setFilter = configClass.getMethod("setObjectInputFilter",
						new Class[] { ObjectInputStream.class, filterClass });
				streamMethods = false;
			}
			Method createFilter = configClass.getMethod("createFilter", new Class[] { String.class });
			Object filter = createFilter.invoke(null, new Object[] { LIMITS_FILTER_PATTERN });
			Object currentFilter = streamMethods ? getFilter.invoke(this, new Object[0])
					: getFilter.invoke(null, new Object[] { this });
			if (currentFilter != null) {
				filter = chainFilters(filterClass, filter, currentFilter);
			}
			if (streamMethods) {
				setFilter.invoke(this, new Object[] { filter });
			} else {
				setFilter.invoke(null, new Object[] { this, filter });
			}
		} catch (Exception e) {
			LogLog.debug("Serialization filter limits not available, relying on the collection count limit only.", e);
		}
	}

	/**
	 * Returns a filter that rejects whatever <code>limits</code> rejects and
	 * otherwise defers to <code>next</code>.
	 */
	private static Object chainFilters(Class filterClass, final Object limits, final Object next) {
		return Proxy.newProxyInstance(HardenedObjectInputStream.class.getClassLoader(), new Class[] { filterClass },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
						try {
							if ("checkInput".equals(method.getName())) {
								Object status = method.invoke(limits, args);
								if ("REJECTED".equals(String.valueOf(status))) {
									return status;
								}
							}
							return method.invoke(next, args);
						} catch (InvocationTargetException e) {
							throw e.getTargetException();
						}
					}
				});
	}

	protected void addToWhitelist(List additionalAuthorizedClasses) {
		whitelistedClassNames.addAll(additionalAuthorizedClasses);
	}
}