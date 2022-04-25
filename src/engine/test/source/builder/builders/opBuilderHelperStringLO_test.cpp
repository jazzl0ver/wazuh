/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <vector>

#include <baseTypes.hpp>

#include "testUtils.hpp"
#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

// Build ok
TEST(opBuilderHelperStringLO, Builds)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "field2normalize": "+s_lo/abcd"
                }
            }
        ]
    })"};
    ASSERT_NO_THROW(bld::opBuilderHelperStringLO(doc.get("/normalize"), tr));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringLO, Builds_incorrect_number_of_arguments)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "field2normalize": "+s_lo/test_value/test_value2"
                }
            }
        ]
    })"};
    ASSERT_THROW(bld::opBuilderHelperStringLO(doc.get("/normalize"), tr), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringLO, Static_string_ok)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieltToCreate": "+s_lo/asd123ASD"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"not_fieltToCreate": "qwe"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"not_fieltToCreate": "ASD123asd"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"not_fieltToCreate": "ASD"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieltToCreate").GetString(), "asd123asd");
    ASSERT_STREQ(expected[1]->getEvent()->get("/fieltToCreate").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/fieltToCreate").GetString(), "asd123asd");
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringLO, Dynamics_string_ok)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieltToCreate": "+s_lo/$srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"srcField": "qwe"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"srcField": "ASD123asd"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"srcField": "ASD"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieltToCreate").GetString(), "qwe");
    ASSERT_STREQ(expected[1]->getEvent()->get("/fieltToCreate").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/fieltToCreate").GetString(), "asd");
}

TEST(opBuilderHelperStringLO, Multilevel_dst)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "a.b.fieltToCreate.2": "+s_lo/$a.b.c.srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b/fieltToCreate/2").GetString(), "qwe");
    ASSERT_STREQ(expected[1]->getEvent()->get("/a/b/fieltToCreate/2").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/a/b/fieltToCreate/2").GetString(), "asd");
}

TEST(opBuilderHelperStringLO, Exist_dst)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "a.b": "+s_lo/$a.b.c.srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b").GetString(), "qwe");
    ASSERT_STREQ(expected[1]->getEvent()->get("/a/b").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/a/b").GetString(), "asd");
}

TEST(opBuilderHelperStringLO, Not_exist_src)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "a.b": "+s_lo/$srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b": "QWE"}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"c": {"d": "QWE123"}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b").GetString(), "QWE");
    ASSERT_FALSE(expected[1]->getEvent()->exists("/a/b"));
}

TEST(opBuilderHelperStringLO, Src_not_string)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieltToCreate": "+s_lo/$srcField123"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"srcField": "qwe"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"srcField": "ASD123asd"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"srcField": "ASD"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_FALSE(expected[0]->getEvent()->exists("/fieltToCreate"));
    ASSERT_FALSE(expected[1]->getEvent()->exists("/fieltToCreate"));
    ASSERT_FALSE(expected[2]->getEvent()->exists("/fieltToCreate"));
}

TEST(opBuilderHelperStringLO, Multilevel_src)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieltToCreate": "+s_lo/$a.b.c.srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieltToCreate").GetString(), "qwe");
    ASSERT_STREQ(expected[1]->getEvent()->get("/fieltToCreate").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/fieltToCreate").GetString(), "asd");
}

TEST(opBuilderHelperStringLO, MultiLevel_dst)
{
    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "a.b": "+s_lo/$a.b.c.srcField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "qwe"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD123asd"}}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b": {"c": {"srcField": "ASD"}}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringLO(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b").GetString(), "qwe");
    ASSERT_STREQ(expected[1]->getEvent()->get("/a/b").GetString(), "asd123asd");
    ASSERT_STREQ(expected[2]->getEvent()->get("/a/b").GetString(), "asd");
}
