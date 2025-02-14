#include "base/logging.hpp"
#include "cmdArgParser.hpp"
#include <indexerConnector/indexerConnector.hpp>
#include <iomanip>
#include <iostream>
#include <random>

static std::random_device RD;
static std::mt19937 ENG(RD());

std::string generateRandomString(size_t length)
{
    const char alphanum[] = "0123456789"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);

    std::uniform_int_distribution<> distr(0, sizeof(alphanum) - 2);

    for (size_t i = 0; i < length; ++i)
    {
        result += alphanum[distr(ENG)];
    }

    return result;
}

float generateRandomFloat(float min, float max)
{
    std::uniform_real_distribution<float> distr(min, max);
    return distr(ENG);
}

int generateRandomInt(int min, int max)
{
    std::uniform_int_distribution distr(min, max);
    return distr(ENG);
}

// Generate timestamp.
std::string generateTimestamp()
{
    std::time_t t = std::time(nullptr);
    std::tm tm {};
    localtime_r(&t, &tm);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
    return ss.str();
}

nlohmann::json fillWithRandomData(const nlohmann::json& templateJson)
{
    nlohmann::json result;

    for (auto& [key, value] : templateJson.items())
    {
        if (value.is_object())
        {
            if (key == "properties")
            {
                result.merge_patch(fillWithRandomData(value));
            }
            else
            {
                result[key] = fillWithRandomData(value);
            }
        }
        else if (key == "type")
        {
            if (value.get<std::string>() == "keyword")
            {
                result = generateRandomString(10);
            }
            else if (value.get<std::string>() == "long")
            {
                result = generateRandomInt(0, 1000);
            }
            else if (value.get<std::string>() == "float")
            {
                result = generateRandomFloat(0.0, 100.0);
            }
            else if (value.get<std::string>() == "date")
            {
                result = generateTimestamp();
            }
        }
    }

    return result;
}

void fillConfiguration(IndexerConnectorOptions& indexerConnectorOptions, const nlohmann::json& config)
{
    if (config.contains("name"))
    {
        indexerConnectorOptions.name = config.at("name").get_ref<const std::string&>();
    }

    if (config.contains("hosts"))
    {
        indexerConnectorOptions.hosts = config.at("hosts");
    }

    if (config.contains("ssl"))
    {
        if (config.at("ssl").contains("certificate_authorities")
            && !config.at("ssl").at("certificate_authorities").empty())
        {
            indexerConnectorOptions.sslOptions.cacert = config.at("ssl").at("certificate_authorities");
        }

        if (config.at("ssl").contains("certificate"))
        {
            indexerConnectorOptions.sslOptions.cert = config.at("ssl").at("certificate").get_ref<const std::string&>();
        }

        if (config.at("ssl").contains("key"))
        {
            indexerConnectorOptions.sslOptions.key = config.at("ssl").at("key").get_ref<const std::string&>();
        }

        if (config.at("ssl").contains("verify_certificates"))
        {
            indexerConnectorOptions.sslOptions.skipVerifyPeer = true; // Default value.
        }

        if (config.at("ssl").contains("merged_ca_path"))
        {
            indexerConnectorOptions.sslOptions.mergedCaPath =
                config.at("ssl").at("merged_ca_path").get_ref<const std::string&>();
        }
    }

    if (config.contains("username"))
    {
        indexerConnectorOptions.username = config.at("username");
    }

    if (config.contains("password"))
    {
        indexerConnectorOptions.password = config.at("password");
    }
}

int main(const int argc, const char* argv[])
{
    try
    {

        CmdLineArgs cmdArgParser(argc, argv);
        logging::start({cmdArgParser.getLogFilePath(), logging::Level::Debug});

        // Read configuration file.
        std::ifstream configurationFile(cmdArgParser.getConfigurationFilePath());
        if (!configurationFile.is_open())
        {
            throw std::invalid_argument("Could not open configuration file.");
        }
        // Parse configuration
        const auto configuration = nlohmann::json::parse(configurationFile);
        IndexerConnectorOptions indexerConnectorOptions;
        fillConfiguration(indexerConnectorOptions, configuration);

        // Create indexer connector.
        IndexerConnector indexerConnector(indexerConnectorOptions);

        // Read events file.
        // If the events file path is empty, then the events are generated
        // automatically.
        if (!cmdArgParser.getEventsFilePath().empty())
        {
            std::ifstream eventsFile(cmdArgParser.getEventsFilePath());
            if (!eventsFile.is_open())
            {
                throw std::invalid_argument("Could not open events file.");
            }
            const auto events = nlohmann::json::parse(eventsFile);

            indexerConnector.publish(events.dump());
        }
        else if (cmdArgParser.getAutoGenerated())
        {
            const auto eventsNumber = cmdArgParser.getNumberOfEvents();
            // Read template file.

            std::ifstream templateFile(cmdArgParser.getTemplateFilePath());
            if (!templateFile.is_open())
            {
                throw std::invalid_argument("Could not open template file.");
            }

            nlohmann::json templateData;
            templateFile >> templateData;

            if (eventsNumber == 0)
            {
                throw std::invalid_argument("Number of events must be greater than 0.");
            }
            else
            {
                for (size_t i = 0; i < eventsNumber; ++i)
                {
                    nlohmann::json randomData =
                        fillWithRandomData(templateData.at("template").at("mappings").at("properties"));
                    nlohmann::json event;
                    event["id"] = generateRandomString(20);
                    event["operation"] = "INSERT";
                    event["data"] = std::move(randomData);

                    indexerConnector.publish(event.dump());
                }
            }
        }

        if (cmdArgParser.getWaitTime() > 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(cmdArgParser.getWaitTime()));
        }
        else
        {
            std::cout << "Press enter to stop the indexer connector tool... \n";
            std::cin.get();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
