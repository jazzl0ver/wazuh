/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HW_ELEMENT_HPP
#define _HW_ELEMENT_HPP

#include "../../wcsModel/inventorySystemHarvester.hpp"

template<typename TContext>
class HwElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~HwElement() = default;
    // LCOV_EXCL_STOP

    static InventorySystemHarvester build(TContext* data)
    {
        InventorySystemHarvester system;

        // TO-DO
        // Field population based on the context.

        return system;
    }
};

#endif // _HW_ELEMENT_HPP
