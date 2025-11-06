/* FilteredSunRsaSign.java
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
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * FilteredSunRsaSign is a custom security provider that filters out
 * non-cryptographic services from the original SunRsaSign provider.
 *
 * It retains only the services related to RSA (RSA and RSASSA-PSS) KeyFactory:
 *     - KeyFactory.RSA
 *     - KeyFactory.RSASSA-PSS
 */
public class FilteredSunRsaSign extends Provider {

    public FilteredSunRsaSign() {

        super("FilteredSunRsaSign",
            Double.parseDouble(
                System.getProperty("java.specification.version")),
            "Filtered SunRsaSign for non-crypto ops");

        try {
            System.err.println("Loading original SunRsaSign...");
            Class<?> originalClass =
                Class.forName("sun.security.rsa.SunRsaSign");
            Provider original =
                (Provider) originalClass.getDeclaredConstructor().newInstance();
            System.err.println("Original SunRsaSign loaded. " +
                "Services available: " + original.getServices().size());

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

            System.err.println("FilteredSunRsaSign initialized " +
                "successfully with " + getServices().size() + " services.");

        } catch (Exception e) {
            System.err.println("Failed to initialize FilteredSunRsaSign");
            e.printStackTrace(System.err);
            throw new RuntimeException(
                "Failed to load and copy from original SunRsaSign", e);
        }
    }

    /**
     * Checks if the given service is supported by this provider.
     * This is the filtering logic that determines which services
     * are retained in the FilteredSunRsaSign provider.
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
            case "KeyFactory":
                if (algo.equals("RSA") || algo.equals("RSASSA-PSS")) {
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
    private void copyService(Provider.Service originalService) {
        try {
            /* Get Class name */
            Field classNameField =
                Provider.Service.class.getDeclaredField("className");
            classNameField.setAccessible(true);
            String className = (String) classNameField.get(originalService);

            /* Get aliases */
            Field aliasesField =
                Provider.Service.class.getDeclaredField("aliases");
            aliasesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            List<String> aliases =
                (List<String>) aliasesField.get(originalService);

            /* Get attributes, build new attributes map */
            Field attributesField =
                Provider.Service.class.getDeclaredField("attributes");
            attributesField.setAccessible(true);

            @SuppressWarnings("unchecked")
            Map<?, ?> rawAttributes =
                (Map<?, ?>) attributesField.get(originalService);
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

            /* Create custom service that delegates to original service
             * for instantiation */
            Provider.Service delegatingService = new Provider.Service(
                this, originalService.getType(), originalService.getAlgorithm(),
                className, aliases != null ? new ArrayList<>(aliases) :
                    null, attributes) {

                @Override
                public Object newInstance(Object constructorParameter)
                    throws NoSuchAlgorithmException {
                    /* Delegate to the original service for instantiation */
                    return originalService.newInstance(constructorParameter);
                }
            };

            putService(delegatingService);

        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException("Failed to copy service: " +
                originalService.getType() + "/" +
                originalService.getAlgorithm(), e);
        }
    }
}

