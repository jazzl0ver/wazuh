#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "LogQLParser.hpp"
#include "SpecificParsers.hpp"
#include "hlp.hpp"

using ParserList = std::vector<Parser>;

void executeParserList(std::string const &event, ParserList const &parsers, ParseResult &result) {
    const char *eventIt = event.c_str();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool error = false;
    printf("%30s | %4s | %4s | %4s\n", "Capture", "type", "comb", "etok");
    printf("-------------------------------|------|------|------\n");
    for (auto const &parser : parsers) {
        printf("%-30s | %4i | %4i | '%1c'\n",
               parser.captureOpts[0].c_str(),
               parser.parserType,
               parser.combType,
               parser.endToken);

        switch (parser.parserType) {
            case ParserType::Any: {
                auto ret = parseAny(&eventIt, parser.endToken);
                if (!ret.empty()) {
                    result[parser.captureOpts[0]] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::Literal: {
                if (!matchLiteral(&eventIt, parser.captureOpts[0])) {
                    fprintf(stderr, "Failed matching literal string\n");
                    error = true;
                }
                break;
            }
            case ParserType::URL: {
                URLResult urlResult;
                if (parseURL(&eventIt, parser.endToken, urlResult)) {
                    result["url.domain"] = std::move(urlResult.domain);
                    result["url.fragment"] = std::move(urlResult.fragment);
                    result["url.original"] = std::move(urlResult.original);
                    result["url.password"] = std::move(urlResult.password);
                    result["url.username"] = std::move(urlResult.username);
                    result["url.scheme"] = std::move(urlResult.scheme);
                    result["url.query"] = std::move(urlResult.query);
                    result["url.path"] = std::move(urlResult.path);
                    result["url.port"] = std::move(urlResult.port);
                }
                else{
                    error = true;
                }
                break;
            }
            case ParserType::IP: {
                auto ret = parseIPaddress(&eventIt, parser.endToken);
                if (!ret.empty()) {
                    result[parser.captureOpts[0]] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            case ParserType::JSON: {
                auto ret = parseJson(&eventIt);
                if (!ret.empty()) {
                    result["json"] = ret;
                }
                else {
                    error = true;
                }
                break;
            }
            default: {
                fprintf(stderr,
                        "Missing implementation for parser type: [%i]\n",
                        parser.parserType);
                break;
            }
        }

        if (error) {
            break;
        }
    }
}

ParserFn getParserOp(std::string const &logQl) {
    ParserList parserList = parseLogQlExpr(logQl);

    ParserFn parseFn = [expr = logQl, parserList = std::move(parserList)](std::string const &event) {
        printf("event:\n\t%s\n\t%s\n\n", event.c_str(), expr.c_str());
        ParseResult result;
        executeParserList(event, parserList, result);
        return result;
    };

    return parseFn;
}
