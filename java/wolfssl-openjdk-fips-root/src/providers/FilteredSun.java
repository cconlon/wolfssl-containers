/* FilteredSun.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
package com.wolfssl.security.providers;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * FilteredSun is a custom security provider that filters out
 * non-cryptographic services from the original SUN provider.
 *
 * It retains only the services:
 *     - CertPathBuilder.PKIX
 *     - CertStore.Collection
 *     - CertStore.com.sun.security.IndexedCollection
 *     - CertificateFactory.X.509
 *     - Configuration.JavaLoginConfig
 *     - Policy.JavaPolicy
 */
public class FilteredSun extends Provider {

    public FilteredSun() {

        super("FilteredSun",
            Double.parseDouble(
                System.getProperty("java.specification.version")),
            "Filtered SUN for non-crypto ops");

        try {
            System.err.println("Loading original SUN...");
            Class<?> originalClass = Class.forName("sun.security.provider.Sun");
            Provider original =
                (Provider) originalClass.getDeclaredConstructor().newInstance();
            System.err.println("Original SUN loaded. Services available: " +
                original.getServices().size());

            Set<Provider.Service> services = original.getServices();
            for (Provider.Service s : services) {
                if (serviceSupported(s)) {
                    System.err.println("Copying " + s.getType() + "." +
                        s.getAlgorithm() + " with class: " +
                        s.getClassName() + ", attributes: " +
                        s.getAttribute("SupportedKeyClasses"));
                    copyService(s);
                }
            }

            System.err.println("FilteredSun initialized successfully with " +
                getServices().size() + " services.");

        } catch (Exception e) {
            System.err.println("Failed to initialize FilteredSun");
            e.printStackTrace(System.err);
            throw new RuntimeException(
                "Failed to load and copy from original SUN", e);
        }
    }

    /**
     * Checks if the given service is supported by this provider.
     * This is the filtering logic that determines which services
     * are retained in the FilteredSun provider.
     *
     * Edit this method to change the filtering logic.
     *
     * @param service the service to check
     *
     * @return true if the service is supported, false otherwise
     */
    public boolean serviceSupported(Provider.Service service) {

        String type = service.getType();
        String algo = service.getAlgorithm();

        switch (type) {
            case "CertPathBuilder":
                if (algo.equals("PKIX")) {
                    return true;
                }
                break;
            case "CertStore":
                if (algo.equals("Collection") ||
                    algo.equals("com.sun.security.IndexedCollection")) {
                    return true;
                }
                break;
            case "CertificateFactory":
                if (algo.equals("X.509")) {
                    return true;
                }
                break;
            case "Configuration":
                if (algo.equals("JavaLoginConfig")) {
                    return true;
                }
                break;
            case "Policy":
                if (algo.equals("JavaPolicy")) {
                    return true;
                }
                break;
            default:
                break;
        }

        return false;
    }

    /**
     * Delegate original service instantiation to the original
     * Provider.Service instance.
     *
     * This method uses reflection to access private fields and copy the
     * necessary attributes from the original service.
     *
     * @param originalService the original service to copy
     */
    private void copyService(Provider.Service s) {
        try {
            /* Get Class name */
            Field classNameField =
                Provider.Service.class.getDeclaredField("className");
            classNameField.setAccessible(true);
            String className = (String) classNameField.get(s);

            /* Get aliases */
            Field aliasesField =
                Provider.Service.class.getDeclaredField("aliases");
            aliasesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            List<String> aliases = (List<String>) aliasesField.get(s);

            /* Get attributes, build new attributes map */
            Field attributesField =
                Provider.Service.class.getDeclaredField("attributes");
            attributesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            Map<?, ?> rawAttributes = (Map<?, ?>) attributesField.get(s);
            Map<String, String> attributes = new HashMap<>();
            if (rawAttributes != null) {
                for (Entry<?, ?> entry : rawAttributes.entrySet()) {
                    Object key = entry.getKey();
                    Field stringField =
                        key.getClass().getDeclaredField("string");
                    stringField.setAccessible(true);
                    String originalKey = (String) stringField.get(key);
                    attributes.put(originalKey, (String) entry.getValue());
                }
            }

            Provider.Service newService = new Provider.Service(
                this, s.getType(), s.getAlgorithm(), className,
                aliases != null ? new ArrayList<>(aliases) : null, attributes);

            putService(newService);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to copy service: " +
                s.getType() + "/" + s.getAlgorithm(), e);
        }
    }
}

