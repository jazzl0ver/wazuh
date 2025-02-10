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

#ifndef _REGISTRY_KEY_ELEMENT_HPP
#define _REGISTRY_KEY_ELEMENT_HPP

#include "../../wcsModel/data.hpp"
#include "../../wcsModel/fimRegistryHarvester.hpp"
#include "../../wcsModel/noData.hpp"
#include "stringHelper.h"
#include "timeHelper.h"

template<typename TContext>
class RegistryKeyElement final
{
public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~RegistryKeyElement() = default;
    // LCOV_EXCL_STOP

    static DataHarvester<FimRegistryInventoryHarvester> build(TContext* data)
    {
        DataHarvester<FimRegistryInventoryHarvester> element;
        element.id = data->agentId();
        element.id += "_";
        element.id += data->path();
        element.operation = "INSERTED";

        element.data.agent.id = data->agentId();
        element.data.agent.name = data->agentName();
        element.data.agent.version = data->agentVersion();
        element.data.agent.ip = data->agentIp();

        element.data.registry.hive = data->hive();
        element.data.registry.key = data->key();
        element.data.registry.uid = data->uid();
        element.data.registry.owner = data->userName();
        element.data.registry.gid = data->gid();
        element.data.registry.group = data->groupName();
        element.data.registry.arch = data->arch();
        element.data.registry.mtime = data->mtimeISO8601();
        return element;
    }

    static NoDataHarvester deleteElement(TContext* data)
    {
        NoDataHarvester element;
        element.operation = "DELETED";
        element.id = data->agentId();
        element.id += "_";
        element.id += data->path();
        return element;
    }
};

#endif // _REGISTRY_KEY_ELEMENT_HPP
